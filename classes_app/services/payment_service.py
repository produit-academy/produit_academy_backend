import logging
import razorpay
from django.db import transaction
from django.conf import settings
from django.utils import timezone
from classes_app.models import Booking, Enrollment, PaymentTransaction, BookingSchedule, ClassSession
from api.views import send_html_email

logger = logging.getLogger(__name__)

def get_razorpay_client():
    if settings.RAZORPAY_KEY_ID and settings.RAZORPAY_KEY_SECRET:
        return razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
    return None

def confirm_booking_payment(booking_id, razorpay_order_id, razorpay_payment_id, signature=None, raw_data=None):
    """
    Idempotently confirms booking payment.
    Can be safely called by both the client-side verify endpoint and the server-side webhook.
    """
    with transaction.atomic():
        # Lock row to prevent race conditions between frontend verify & webhook
        booking = Booking.objects.select_for_update().get(pk=booking_id)

        # Update or record transaction
        tx, _ = PaymentTransaction.objects.update_or_create(
            razorpay_order_id=razorpay_order_id,
            defaults={
                'booking': booking,
                'user': booking.student,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': signature,
                'amount': booking.total_amount,
                'currency': 'INR',
                'status': 'captured',
                'raw_response': raw_data or {}
            }
        )

        # If already confirmed, simply return existing state without duplicate sessions/emails
        if booking.booking_status == 'confirmed' and booking.payment_status in ['advance_paid', 'fully_paid']:
            logger.info(f"Booking {booking_id} is already confirmed. Skipping re-processing.")
            return booking, False

        # Mark booking as confirmed
        booking.payment_status = 'advance_paid'
        booking.booking_status = 'confirmed'
        if razorpay_order_id:
            booking.razorpay_order_id = razorpay_order_id
        if razorpay_payment_id:
            booking.razorpay_payment_id = razorpay_payment_id
        if signature:
            booking.razorpay_signature = signature
        booking.save()

        # Create student enrollment
        Enrollment.objects.get_or_create(
            student=booking.student,
            course=booking.course,
            defaults={'teacher': booking.teacher}
        )

        # Generate sessions and link schedules
        from classes_app.views_booking import DummyPaymentView
        handler = DummyPaymentView()
        schedules = handler._process_schedules(booking)
        handler._send_booking_emails(booking, schedules)

        # Send HTML receipt to student
        schedule_text = "\n".join([
            f"• {s.date.strftime('%A, %b %d, %Y')} at {s.start_time.strftime('%I:%M %p')}"
            for s in schedules
        ])
        try:
            send_html_email(
                f"Booking & Payment Confirmed: {booking.subject.name}",
                booking.student.email,
                f"{booking.student.first_name} {booking.student.last_name}".strip() or booking.student.username,
                type='payment_confirmed',
                amount=str(booking.advance_amount),
                subject_name=f"{booking.subject.name} ({booking.course.name})",
                order_id=razorpay_order_id or '',
                payment_id=razorpay_payment_id or '',
                schedule_text=schedule_text,
            )
        except Exception as e:
            logger.error(f"Error sending payment confirmation email to {booking.student.email}: {e}")

        logger.info(f"Booking {booking_id} successfully confirmed with payment ID: {razorpay_payment_id}")
        return booking, True


def recheck_razorpay_payment(order_id_or_booking_id):
    """
    Directly queries Razorpay's API to inspect the status of an order/payment.
    Reconciles the database state idempotently.
    """
    client = get_razorpay_client()
    if not client:
        return {'success': False, 'error': 'Razorpay gateway credentials not configured.'}

    # Find the booking and transaction
    booking = None
    if isinstance(order_id_or_booking_id, int) or str(order_id_or_booking_id).isdigit():
        booking = Booking.objects.filter(pk=int(order_id_or_booking_id)).first()
    
    if not booking:
        booking = Booking.objects.filter(razorpay_order_id=str(order_id_or_booking_id)).first()
    
    if not booking:
        tx = PaymentTransaction.objects.filter(razorpay_order_id=str(order_id_or_booking_id)).first()
        if tx:
            booking = tx.booking

    if not booking:
        return {'success': False, 'error': 'Booking not found.'}

    order_id = booking.razorpay_order_id
    if not order_id:
        return {'success': False, 'error': 'No Razorpay order ID associated with this booking.'}

    try:
        order = client.order.fetch(order_id)
        payments_data = client.order.payments(order_id)
        payment_items = payments_data.get('items', []) if isinstance(payments_data, dict) else []

        logger.info(f"Rechecked order {order_id}: status={order.get('status')}, payments={len(payment_items)}")

        # Find captured payment
        captured_payment = None
        for p in payment_items:
            if p.get('status') == 'captured':
                captured_payment = p
                break

        if captured_payment:
            payment_id = captured_payment.get('id')
            b, newly_confirmed = confirm_booking_payment(
                booking_id=booking.id,
                razorpay_order_id=order_id,
                razorpay_payment_id=payment_id,
                raw_data={'verified_via': 'recheck_gateway', 'order': order, 'payment': captured_payment}
            )
            return {
                'success': True,
                'status': 'captured',
                'payment_id': payment_id,
                'booking_status': b.booking_status,
                'payment_status': b.payment_status,
                'message': 'Payment confirmed from gateway as Captured.',
                'newly_confirmed': newly_confirmed
            }

        # Check if there was an explicit failed payment
        failed_payment = None
        for p in payment_items:
            if p.get('status') == 'failed':
                failed_payment = p
                break

        if failed_payment:
            PaymentTransaction.objects.filter(razorpay_order_id=order_id).update(
                status='failed',
                error_code=failed_payment.get('error_code', ''),
                error_description=failed_payment.get('error_description', ''),
                raw_response={'recheck_failed': failed_payment}
            )
            return {
                'success': True,
                'status': 'failed',
                'error_code': failed_payment.get('error_code'),
                'error_description': failed_payment.get('error_description'),
                'message': 'Gateway reports payment as Failed.'
            }

        return {
            'success': True,
            'status': order.get('status', 'created'),
            'message': f"Order exists in gateway with status '{order.get('status')}'. No captured payment yet."
        }

    except Exception as e:
        logger.error(f"Error querying Razorpay for order {order_id}: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def reconcile_payment(booking_id, admin_user, reason, action='mark_paid'):
    """
    Manually reconciles a payment by an authorized admin with audit logging.
    """
    with transaction.atomic():
        booking = Booking.objects.select_for_update().get(pk=booking_id)

        if action == 'mark_paid':
            booking.payment_status = 'advance_paid'
            booking.booking_status = 'confirmed'
            booking.save()

            Enrollment.objects.get_or_create(
                student=booking.student,
                course=booking.course,
                defaults={'teacher': booking.teacher}
            )

            from classes_app.views_booking import DummyPaymentView
            handler = DummyPaymentView()
            schedules = handler._process_schedules(booking)
            handler._send_booking_emails(booking, schedules)

            PaymentTransaction.objects.create(
                booking=booking,
                user=booking.student,
                razorpay_order_id=booking.razorpay_order_id or f"manual_{booking.id}",
                amount=booking.total_amount,
                currency='INR',
                status='captured',
                raw_response={'manual_reconcile': True, 'reconciled_by': admin_user.email, 'reason': reason}
            )

            return {'success': True, 'message': f'Booking #{booking_id} manually reconciled and confirmed.'}

        elif action == 'mark_failed':
            booking.payment_status = 'pending'
            booking.booking_status = 'cancelled'
            booking.save()

            PaymentTransaction.objects.filter(booking=booking).update(
                status='failed',
                error_description=f"Manually marked as failed by {admin_user.email}: {reason}"
            )
            return {'success': True, 'message': f'Booking #{booking_id} marked as failed.'}

        return {'success': False, 'error': f'Invalid action {action}'}

