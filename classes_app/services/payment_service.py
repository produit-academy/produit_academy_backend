import logging
from django.db import transaction
from classes_app.models import Booking, Enrollment, PaymentTransaction

logger = logging.getLogger(__name__)

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
        if booking.booking_status == 'confirmed' and booking.payment_status == 'advance_paid':
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

        logger.info(f"Booking {booking_id} successfully confirmed with payment ID: {razorpay_payment_id}")
        return booking, True
