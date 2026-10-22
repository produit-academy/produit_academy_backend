import logging
from decimal import Decimal
from django.db import transaction
from django.utils import timezone
from api.models import StaffWallet, WalletTransaction
from classes_app.models import ClassSession, Booking

logger = logging.getLogger(__name__)


def credit_teacher_for_completed_session(session_id):
    """
    Credits the teacher's StaffWallet when a class session is completed.
    
    Guarantees:
    - 100% idempotent: If already credited, does not double-credit.
    - Thread-safe: Uses select_for_update inside an atomic transaction.
    - Audit trail: Links the created WalletTransaction back to the session.
    - Booking sync: If all sessions in the booking are completed, marks the booking as completed.
    """
    with transaction.atomic():
        try:
            session = ClassSession.objects.select_for_update().get(pk=session_id)
        except ClassSession.DoesNotExist:
            logger.error(f"ClassSession #{session_id} not found for wallet crediting.")
            return None

        # Idempotency check
        if session.is_wallet_credited:
            logger.info(f"ClassSession #{session_id} has already been credited.")
            return session.wallet_transaction

        # Only completed sessions are eligible for payout
        if session.status != 'Completed':
            return None

        teacher = session.teacher
        if not teacher:
            logger.warning(f"ClassSession #{session_id} has no teacher assigned.")
            return None

        # Determine teacher payout amount per class
        payout_amount = Decimal('0.00')
        booking = None

        # Check if session is linked to a booking schedule
        booking_schedule = getattr(session, 'booking_schedule', None)
        if booking_schedule and booking_schedule.booking:
            booking = booking_schedule.booking
            payout_amount = booking.teacher_fee_per_class or Decimal('0.00')

        # Fallback to teacher profile hourly_rate if no booking (or 0 rate in booking)
        if payout_amount <= Decimal('0.00'):
            profile = getattr(teacher, 'classes_teacher_profile', None)
            if profile and profile.hourly_rate:
                payout_amount = profile.hourly_rate

        # If rate is 0 or negative, mark credited without transaction
        if payout_amount <= Decimal('0.00'):
            session.is_wallet_credited = True
            session.wallet_credited_at = timezone.now()
            session.save(update_fields=['is_wallet_credited', 'wallet_credited_at'])
            return None

        # Get or create teacher's wallet with lock
        wallet, _ = StaffWallet.objects.select_for_update().get_or_create(staff=teacher)

        # Build clear audit note
        student_display = ""
        if session.student:
            student_display = f" - Student: {session.student.get_full_name() or session.student.username}"
        elif booking and booking.student:
            student_display = f" - Student: {booking.student.get_full_name() or booking.student.username}"

        course_name = session.course.name if session.course else "Class"
        session_title = session.title or course_name
        note = f"Payout for Completed Class #{session.id}: {session_title}{student_display}"

        # Create wallet credit transaction
        tx = WalletTransaction.objects.create(
            wallet=wallet,
            type='credit',
            amount=payout_amount,
            note=note
        )

        # Update wallet total_earned
        wallet.total_earned += payout_amount
        wallet.save(update_fields=['total_earned', 'updated_at'])

        # Mark session as credited
        session.is_wallet_credited = True
        session.wallet_credited_at = timezone.now()
        session.wallet_transaction = tx
        session.save(update_fields=['is_wallet_credited', 'wallet_credited_at', 'wallet_transaction'])

        logger.info(f"Successfully credited ₹{payout_amount} to teacher {teacher.email} for session #{session.id}")

        # Check if all sessions in this booking are completed
        if booking:
            all_schedules = booking.schedules.all()
            if all_schedules.exists() and all(s.status == 'completed' for s in all_schedules):
                if booking.booking_status != 'completed':
                    booking.booking_status = 'completed'
                    booking.save(update_fields=['booking_status'])

        return tx
