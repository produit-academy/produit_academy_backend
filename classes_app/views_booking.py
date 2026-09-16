"""
New views for course browsing flow, teacher profiles, booking, and payment.
"""
import json
import logging
import razorpay
from datetime import timedelta, date as dt_date
from decimal import Decimal

from django.utils import timezone
from django.db.models import Count, Q
from django.core.mail import send_mail
from django.core.cache import cache
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import permissions, status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from api.models import User
from .models import (
    Course, Subject, TeacherProfile, TeacherAvailability,
    TeacherDemoVideo, Booking, BookingSchedule, ClassSession,
    Enrollment, EmailLog, PLATFORM_FEE, PaymentTransaction,
)
from .services.payment_service import confirm_booking_payment, recheck_razorpay_payment, reconcile_payment

logger = logging.getLogger(__name__)

def get_razorpay_client():
    return razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

from .serializers import (
    SubjectSerializer, TeacherProfileCardSerializer,
    TeacherProfileDetailSerializer, TeacherDemoVideoSerializer,
    BookingSerializer, BookingCreateSerializer, BookingScheduleSerializer,
    TeacherAvailabilitySerializer,
)


class IsClassesPlatform(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_staff or request.user.is_superuser:
            return True
        return request.user.platform == 'classes'


class IsTeacher(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == 'teacher' or request.user.is_staff or request.user.is_superuser
        )


# ============================================================
# PUBLIC BROWSING ENDPOINTS
# ============================================================

class SubjectListView(generics.ListAPIView):
    """List subjects for a given course."""
    permission_classes = [permissions.AllowAny]
    serializer_class = SubjectSerializer

    def get_queryset(self):
        course_id = self.request.query_params.get('course_id')
        qs = Subject.objects.filter(is_active=True).annotate(
            _teacher_count=Count('teachers', filter=Q(teachers__is_approved=True), distinct=True)
        )
        if course_id:
            qs = qs.filter(course_id=course_id)
        return qs.select_related('course')

    def list(self, request, *args, **kwargs):
        course_id = request.query_params.get('course_id', 'all')
        cache_key = f"subjects_course_{course_id}"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=120)  # 2 minutes
        return response


class TeachersBySubjectView(APIView):
    """List approved teachers for a given subject."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        subject_id = request.query_params.get('subject_id')
        if not subject_id:
            return Response({'error': 'subject_id is required'}, status=400)

        cache_key = f"teachers_subject_{subject_id}"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        try:
            subject = Subject.objects.get(id=subject_id, is_active=True)
            subject_name = subject.name
        except Subject.DoesNotExist:
            return Response({'error': 'Subject not found'}, status=404)

        profiles = list(TeacherProfile.objects.filter(
            is_approved=True,
            taught_subjects__id=subject_id
        ).select_related('user').prefetch_related('taught_subjects'))

        # Batch query active availability to avoid N+1 queries
        today = dt_date.today()
        user_ids = [p.user_id for p in profiles]
        available_user_ids = set(
            TeacherAvailability.objects.filter(
                teacher_id__in=user_ids,
                date__gte=today
            ).values_list('teacher_id', flat=True)
        )

        serializer = TeacherProfileCardSerializer(
            profiles, many=True,
            context={
                'request': request,
                'subject_id': int(subject_id),
                'subject_name': subject_name,
                'available_user_ids': available_user_ids,
            }
        )
        cache.set(cache_key, serializer.data, timeout=60)  # 1 minute
        return Response(serializer.data)


class TeacherProfileDetailView(APIView):
    """Full teacher profile for the public detail page."""
    permission_classes = [permissions.AllowAny]

    def get(self, request, pk):
        try:
            profile = TeacherProfile.objects.select_related('user').get(
                user_id=pk, is_approved=True
            )
        except TeacherProfile.DoesNotExist:
            return Response({'error': 'Teacher not found'}, status=404)

        serializer = TeacherProfileDetailSerializer(profile, context={'request': request})
        return Response(serializer.data)


# ============================================================
# STUDENT BOOKING ENDPOINTS
# ============================================================

class StudentBookTeacherView(APIView):
    """Create a booking for a teacher."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request):
        serializer = BookingCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        student = request.user
        if student.role != 'student':
            return Response({'error': 'Only students can book.'}, status=403)

        try:
            teacher = User.objects.get(pk=data['teacher_id'], role='teacher')
            profile = TeacherProfile.objects.get(user=teacher, is_approved=True)
        except (User.DoesNotExist, TeacherProfile.DoesNotExist):
            return Response({'error': 'Teacher not found or not approved.'}, status=404)

        try:
            subject = Subject.objects.get(pk=data['subject_id'], is_active=True)
        except Subject.DoesNotExist:
            return Response({'error': 'Subject not found.'}, status=404)

        # Check for duplicate booking
        existing = Booking.objects.filter(
            student=student, teacher=teacher, subject=subject,
            booking_status='confirmed'
        ).exists()
        if existing:
            return Response({'error': 'You already have an active booking with this teacher for this subject.'}, status=400)

        # Validate slots
        slot_ids = data['slot_ids']
        slots = list(TeacherAvailability.objects.filter(id__in=slot_ids))
        if len(slots) != len(slot_ids):
            return Response({'error': 'One or more selected slots are invalid or unavailable.'}, status=400)
            
        for slot in slots:
            if slot.teacher_id != teacher.id:
                return Response({'error': 'Selected slots do not belong to this teacher.'}, status=400)
            if slot.date < dt_date.today():
                return Response({'error': 'Cannot book slots in the past.'}, status=400)

        # Check if any slot is already booked by another student
        active_schedules = BookingSchedule.objects.filter(
            booking__teacher=teacher,
            booking__booking_status__in=['confirmed', 'completed'],
            status='scheduled'
        )
        booked_times = set((s.date, s.start_time) for s in active_schedules)
        for slot in slots:
            if (slot.date, slot.start_time) in booked_times:
                return Response({
                    'error': f"Slot on {slot.date.strftime('%b %d')} at {slot.start_time.strftime('%I:%M %p')} is already booked by another student. Please select an available slot."
                }, status=400)

        # Calculate derived fields
        slots.sort(key=lambda s: (s.date, s.start_time))
        start_date = slots[0].date
        end_date = slots[-1].date
        preferred_time = slots[0].start_time
        num_classes = len(slots)

        # Calculate fees
        teacher_fee = profile.hourly_rate
        total_teacher_fee = teacher_fee * num_classes
        platform_fee = Decimal(str(PLATFORM_FEE))
        total_amount = total_teacher_fee + platform_fee
        advance_amount = total_amount
        remaining_amount = Decimal('0.00')

        booking = Booking.objects.create(
            student=student,
            teacher=teacher,
            subject=subject,
            course=subject.course,
            start_date=start_date,
            end_date=end_date,
            preferred_time=preferred_time,
            num_classes=num_classes,
            teacher_fee_per_class=teacher_fee,
            platform_fee=platform_fee,
            total_amount=total_amount,
            advance_amount=advance_amount,
            remaining_amount=remaining_amount,
            payment_status='pending',
            booking_status='pending',
            google_meet_link=profile.google_meet_link or '',
        )

        # Create BookingSchedule entries immediately
        for slot in slots:
            BookingSchedule.objects.create(
                booking=booking,
                date=slot.date,
                start_time=slot.start_time,
                end_time=slot.end_time,
                status='scheduled'
            )

        return Response({
            'booking_id': booking.id,
            'teacher_name': f"{teacher.first_name} {teacher.last_name}".strip(),
            'subject': subject.name,
            'num_classes': num_classes,
            'teacher_fee_per_class': float(teacher_fee),
            'platform_fee': float(platform_fee),
            'total_amount': float(total_amount),
            'advance_amount': float(advance_amount),
            'remaining_amount': float(remaining_amount),
            'message': 'Booking created. Proceed to payment.',
        }, status=201)


class DummyPaymentView(APIView):
    """Simulate payment, confirm booking, generate schedule, send emails."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request):
        booking_id = request.data.get('booking_id')
        try:
            booking = Booking.objects.get(pk=booking_id, student=request.user, booking_status='pending')
        except Booking.DoesNotExist:
            return Response({'error': 'Booking not found or already processed.'}, status=404)

        # Update booking status
        booking.payment_status = 'advance_paid'
        booking.booking_status = 'confirmed'
        booking.save()

        # Auto-create enrollment if not exists
        Enrollment.objects.get_or_create(
            student=booking.student, course=booking.course,
            defaults={'teacher': booking.teacher}
        )

        # Generate Class Sessions and Link Schedules
        schedules = self._process_schedules(booking)

        # Send emails
        self._send_booking_emails(booking, schedules)

        return Response({
            'message': 'Payment successful! Booking confirmed.',
            'booking_id': booking.id,
            'schedules_created': len(schedules),
        })

    def _process_schedules(self, booking):
        """Create ClassSession entries for the pre-generated BookingSchedules."""
        from datetime import timedelta as td
        schedules = list(booking.schedules.all())
        
        for schedule in schedules:
            scheduled_dt = timezone.make_aware(
                timezone.datetime.combine(schedule.date, schedule.start_time)
            )
            
            # Create ClassSession
            session = ClassSession.objects.create(
                course=booking.course,
                teacher=booking.teacher,
                student=booking.student,
                title=f"Class: {booking.subject.name}",
                meeting_link=booking.google_meet_link,
                scheduled_time=scheduled_dt,
                duration_minutes=60,
                status='Scheduled',
            )
            
            # Link session to schedule and ensure status is set
            schedule.class_session = session
            schedule.status = 'scheduled'
            schedule.save()

        return schedules

    def _send_booking_emails(self, booking, schedules):
        """Send confirmation emails to student and teacher."""
        student = booking.student
        teacher = booking.teacher
        schedule_text = "\n".join([
            f"  - {s.date.strftime('%A, %b %d')} at {s.start_time.strftime('%I:%M %p')}"
            for s in schedules
        ])

        # Student email
        student_subject = f"Booking Confirmed: {booking.subject.name} with {teacher.first_name} {teacher.last_name}"
        student_body = (
            f"Hello {student.first_name or 'Student'},\n\n"
            f"Your booking has been confirmed!\n\n"
            f"Teacher: {teacher.first_name} {teacher.last_name}\n"
            f"Subject: {booking.subject.name}\n"
            f"Class: {booking.course.name}\n"
            f"Number of Classes: {booking.num_classes}\n"
            f"Schedule:\n{schedule_text}\n\n"
            f"Fee Breakdown:\n"
            f"  Teacher Fee: ₹{booking.teacher_fee_per_class}/class × {booking.num_classes} = ₹{booking.teacher_fee_per_class * booking.num_classes}\n"
            f"  Platform Fee: ₹{booking.platform_fee}\n"
            f"  Total: ₹{booking.total_amount}\n"
            f"  Advance Paid: ₹{booking.advance_amount}\n"
            f"  Remaining: ₹{booking.remaining_amount}\n\n"
            f"Google Meet Link: {booking.google_meet_link or 'Will be shared soon'}\n\n"
            f"Best regards,\nProduit Academy Team"
        )
        self._send_and_log(student.email, student_subject, student_body, 'booking_student', booking)

        # Teacher email
        teacher_subject = f"New Booking: {student.first_name} {student.last_name} for {booking.subject.name}"
        teacher_body = (
            f"Hello {teacher.first_name or 'Teacher'},\n\n"
            f"You have a new booking!\n\n"
            f"Student: {student.first_name} {student.last_name}\n"
            f"Student Email: {student.email}\n"
            f"Student Phone: {student.phone_number or 'Not provided'}\n"
            f"Subject: {booking.subject.name}\n"
            f"Class: {booking.course.name}\n"
            f"Number of Classes: {booking.num_classes}\n"
            f"Schedule:\n{schedule_text}\n\n"
            f"Google Meet Link: {booking.google_meet_link or 'Please update your profile'}\n\n"
            f"Best regards,\nProduit Academy Team"
        )
        self._send_and_log(teacher.email, teacher_subject, teacher_body, 'booking_teacher', booking)

    def _send_and_log(self, email, subject, body, email_type, booking):
        try:
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
            EmailLog.objects.create(
                recipient_email=email, subject=subject,
                email_type=email_type, status='sent', related_booking=booking,
            )
        except Exception as e:
            EmailLog.objects.create(
                recipient_email=email, subject=subject,
                email_type=email_type, status='failed',
                error_message=str(e), related_booking=booking,
            )


class CreateRazorpayOrderView(APIView):
    """Creates an official Razorpay order for a pending booking."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request):
        booking_id = request.data.get('booking_id')
        if not booking_id:
            return Response({'error': 'booking_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            booking = Booking.objects.get(pk=booking_id, student=request.user, booking_status='pending')
        except Booking.DoesNotExist:
            return Response({'error': 'Pending booking not found or already confirmed.'}, status=status.HTTP_404_NOT_FOUND)

        if not settings.RAZORPAY_KEY_ID or not settings.RAZORPAY_KEY_SECRET:
            return Response({'error': 'Razorpay gateway is not configured on the server.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        client = get_razorpay_client()
        amount_in_paise = int(booking.total_amount * 100)

        order_params = {
            'amount': amount_in_paise,
            'currency': 'INR',
            'receipt': f"bk_{booking.id}",
            'notes': {
                'booking_id': str(booking.id),
                'student_id': str(request.user.id),
                'student_email': request.user.email,
                'subject': booking.subject.name,
            }
        }

        try:
            razorpay_order = client.order.create(data=order_params)

            # Save order ID on booking
            booking.razorpay_order_id = razorpay_order['id']
            booking.save(update_fields=['razorpay_order_id'])

            # Log transaction attempt
            PaymentTransaction.objects.create(
                booking=booking,
                user=request.user,
                razorpay_order_id=razorpay_order['id'],
                amount=booking.total_amount,
                currency='INR',
                status='created',
                raw_response=razorpay_order
            )

            return Response({
                'order_id': razorpay_order['id'],
                'amount': razorpay_order['amount'],
                'currency': razorpay_order['currency'],
                'key_id': settings.RAZORPAY_KEY_ID,
                'booking_id': booking.id,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Failed to create Razorpay order for booking {booking.id}: {e}", exc_info=True)
            return Response({'error': f'Failed to create order: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyRazorpayPaymentView(APIView):
    """Verifies HMAC signature from Razorpay checkout and confirms booking."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request):
        booking_id = request.data.get('booking_id')
        razorpay_order_id = request.data.get('razorpay_order_id')
        razorpay_payment_id = request.data.get('razorpay_payment_id')
        razorpay_signature = request.data.get('razorpay_signature')

        if not all([booking_id, razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            return Response({'error': 'Missing required payment verification parameters.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            booking = Booking.objects.get(pk=booking_id, student=request.user)
        except Booking.DoesNotExist:
            return Response({'error': 'Booking not found.'}, status=status.HTTP_404_NOT_FOUND)

        client = get_razorpay_client()
        try:
            client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            })
        except razorpay.errors.SignatureVerificationError:
            logger.warning(f"Signature verification failed for order {razorpay_order_id}")
            return Response({'error': 'Payment verification failed: Invalid signature.'}, status=status.HTTP_400_BAD_REQUEST)

        # Idempotent confirmation
        booking, newly_confirmed = confirm_booking_payment(
            booking_id=booking.id,
            razorpay_order_id=razorpay_order_id,
            razorpay_payment_id=razorpay_payment_id,
            signature=razorpay_signature,
            raw_data={'verified_via': 'client_callback'}
        )

        return Response({
            'message': 'Payment successfully verified and booking confirmed.',
            'booking_id': booking.id,
            'status': 'confirmed'
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class RazorpayWebhookView(APIView):
    """Public webhook endpoint to capture server-to-server Razorpay events."""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        webhook_signature = request.headers.get('X-Razorpay-Signature')
        if not webhook_signature:
            return Response({'error': 'Missing signature header'}, status=status.HTTP_400_BAD_REQUEST)

        webhook_secret = settings.RAZORPAY_WEBHOOK_SECRET
        if not webhook_secret:
            logger.error("RAZORPAY_WEBHOOK_SECRET is not configured.")
            return Response({'error': 'Webhook secret unconfigured'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        body = request.body
        try:
            client = get_razorpay_client()
            client.utility.verify_webhook_signature(body.decode('utf-8'), webhook_signature, webhook_secret)
        except razorpay.errors.SignatureVerificationError:
            logger.warning("Invalid Razorpay webhook signature received.")
            return Response({'error': 'Invalid signature'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error checking webhook signature: {e}")
            return Response({'error': 'Verification error'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            event_data = json.loads(body.decode('utf-8'))
        except Exception:
            return Response({'error': 'Invalid JSON body'}, status=status.HTTP_400_BAD_REQUEST)

        event_name = event_data.get('event')
        logger.info(f"Received Razorpay webhook event: {event_name}")

        if event_name in ['order.paid', 'payment.captured']:
            payload = event_data.get('payload', {})
            order_entity = payload.get('order', {}).get('entity', {})
            payment_entity = payload.get('payment', {}).get('entity', {})

            order_id = order_entity.get('id') or payment_entity.get('order_id')
            payment_id = payment_entity.get('id')
            booking_id = (
                order_entity.get('notes', {}).get('booking_id') or
                payment_entity.get('notes', {}).get('booking_id')
            )

            # Fallback: find booking via PaymentTransaction if notes missing
            if not booking_id and order_id:
                tx = PaymentTransaction.objects.filter(razorpay_order_id=order_id).first()
                if tx:
                    booking_id = tx.booking_id

            if booking_id:
                try:
                    confirm_booking_payment(
                        booking_id=int(booking_id),
                        razorpay_order_id=order_id,
                        razorpay_payment_id=payment_id,
                        raw_data=event_data
                    )
                except Exception as e:
                    logger.error(f"Error in webhook confirming booking {booking_id}: {e}", exc_info=True)

        elif event_name == 'payment.failed':
            payment_entity = event_data.get('payload', {}).get('payment', {}).get('entity', {})
            order_id = payment_entity.get('order_id')
            if order_id:
                PaymentTransaction.objects.filter(razorpay_order_id=order_id).update(
                    status='failed',
                    error_code=payment_entity.get('error_code', ''),
                    error_description=payment_entity.get('error_description', ''),
                    raw_response=event_data
                )

        return Response({'status': 'ok'}, status=status.HTTP_200_OK)


class StudentBookingsListView(generics.ListAPIView):
    """List all bookings for the authenticated student."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]
    serializer_class = BookingSerializer

    def get_queryset(self):
        return Booking.objects.filter(student=self.request.user).exclude(
            booking_status='pending'
        ).select_related(
            'teacher', 'student', 'subject', 'course'
        ).prefetch_related('schedules')


class StudentPaymentHistoryView(APIView):
    """Payment history for student with gateway reference details."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        bookings = Booking.objects.filter(student=request.user).order_by('-created_at')
        
        # Load transactions
        tx_map = {}
        for tx in PaymentTransaction.objects.filter(user=request.user):
            if tx.booking_id not in tx_map:
                tx_map[tx.booking_id] = tx

        data = []
        for b in bookings:
            tx = tx_map.get(b.id)
            # Determine clear student-facing status
            if b.payment_status in ['advance_paid', 'fully_paid']:
                display_status = 'Paid'
            elif tx and tx.status == 'failed':
                display_status = 'Failed'
            elif b.booking_status == 'cancelled':
                display_status = 'Cancelled'
            else:
                display_status = 'Pending'

            data.append({
                'id': b.id,
                'subject': b.subject.name,
                'teacher': f"{b.teacher.first_name} {b.teacher.last_name}".strip() or b.teacher.username,
                'total_amount': float(b.total_amount),
                'advance_paid': float(b.advance_amount),
                'remaining': float(b.remaining_amount),
                'payment_status': b.payment_status,
                'display_status': display_status,
                'booking_status': b.booking_status,
                'razorpay_order_id': b.razorpay_order_id or (tx.razorpay_order_id if tx else None),
                'razorpay_payment_id': b.razorpay_payment_id or (tx.razorpay_payment_id if tx else None),
                'date': b.created_at.isoformat(),
            })

        return Response(data)


# ============================================================
# ADMIN PAYMENT AUDIT & RECONCILIATION
# ============================================================

class AdminPaymentListView(APIView):
    """Admin views all payment transactions with filters and search."""
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        bookings = Booking.objects.all().select_related('student', 'teacher', 'subject', 'course').order_by('-created_at')
        
        # Filters
        status_filter = request.query_params.get('status')
        if status_filter:
            if status_filter == 'paid':
                bookings = bookings.filter(payment_status__in=['advance_paid', 'fully_paid'])
            elif status_filter == 'pending':
                bookings = bookings.filter(payment_status='pending')
            elif status_filter == 'cancelled':
                bookings = bookings.filter(booking_status='cancelled')

        search = request.query_params.get('search', '').strip()
        if search:
            bookings = bookings.filter(
                Q(student__email__icontains=search) |
                Q(student__first_name__icontains=search) |
                Q(teacher__first_name__icontains=search) |
                Q(subject__name__icontains=search) |
                Q(razorpay_order_id__icontains=search) |
                Q(razorpay_payment_id__icontains=search)
            )

        tx_map = {}
        for tx in PaymentTransaction.objects.filter(booking__in=bookings[:200]):
            tx_map[tx.booking_id] = tx

        data = []
        for b in bookings[:100]:
            tx = tx_map.get(b.id)
            data.append({
                'id': b.id,
                'student_name': f"{b.student.first_name} {b.student.last_name}".strip() or b.student.username,
                'student_email': b.student.email,
                'teacher_name': f"{b.teacher.first_name} {b.teacher.last_name}".strip() or b.teacher.username,
                'subject': b.subject.name,
                'course': b.course.name,
                'total_amount': float(b.total_amount),
                'advance_amount': float(b.advance_amount),
                'remaining_amount': float(b.remaining_amount),
                'payment_status': b.payment_status,
                'booking_status': b.booking_status,
                'razorpay_order_id': b.razorpay_order_id or '',
                'razorpay_payment_id': b.razorpay_payment_id or '',
                'gateway_status': tx.status if tx else 'uninitiated',
                'created_at': b.created_at.isoformat(),
            })

        return Response(data)


class AdminPaymentRecheckView(APIView):
    """Admin initiates Razorpay gateway sync to check and update order/payment status."""
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk):
        result = recheck_razorpay_payment(pk)
        if not result.get('success'):
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_200_OK)


class AdminPaymentReconcileView(APIView):
    """Admin manually reconciles a booking payment."""
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk):
        reason = request.data.get('reason', '').strip()
        action = request.data.get('action', 'mark_paid')
        if not reason:
            return Response({'error': 'Reason is required for manual reconciliation.'}, status=400)

        result = reconcile_payment(pk, request.user, reason, action)
        if not result.get('success'):
            return Response(result, status=400)
        return Response(result)


# ============================================================
# TEACHER PROFILE MANAGEMENT
# ============================================================

class TeacherProfileManageView(APIView):
    """Teacher manages their own profile."""
    permission_classes = [permissions.IsAuthenticated, IsTeacher]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        profile, _ = TeacherProfile.objects.get_or_create(user=request.user)
        serializer = TeacherProfileDetailSerializer(profile, context={'request': request})
        return Response(serializer.data)

    def patch(self, request):
        profile, _ = TeacherProfile.objects.get_or_create(user=request.user)
        allowed = ['bio', 'qualification', 'experience', 'skills', 'certifications',
                    'languages', 'teaching_style', 'google_meet_link', 'profile_picture_base64']
        for field in allowed:
            if field in request.data:
                setattr(profile, field, request.data[field])
        if 'profile_picture' in request.FILES:
            profile.profile_picture = request.FILES['profile_picture']
        profile.save()

        user = request.user
        user_updated = False
        if 'first_name' in request.data:
            user.first_name = request.data['first_name']
            user_updated = True
        if 'last_name' in request.data:
            user.last_name = request.data['last_name']
            user_updated = True
        if 'password' in request.data and request.data['password']:
            user.set_password(request.data['password'])
            user_updated = True
        if user_updated:
            user.save()

        return Response({'message': 'Profile updated successfully.'})


class TeacherDemoVideoManageView(APIView):
    """Teacher manages their demo videos."""
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request):
        videos = TeacherDemoVideo.objects.filter(teacher=request.user)
        return Response(TeacherDemoVideoSerializer(videos, many=True).data)

    def post(self, request):
        data = request.data.copy()
        serializer = TeacherDemoVideoSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save(teacher=request.user)
        return Response(serializer.data, status=201)

    def delete(self, request):
        video_id = request.data.get('video_id')
        try:
            video = TeacherDemoVideo.objects.get(pk=video_id, teacher=request.user)
            video.delete()
            return Response({'message': 'Video deleted.'})
        except TeacherDemoVideo.DoesNotExist:
            return Response({'error': 'Video not found.'}, status=404)


class TeacherBookingsView(generics.ListAPIView):
    """List all bookings for the authenticated teacher."""
    permission_classes = [permissions.IsAuthenticated, IsTeacher]
    serializer_class = BookingSerializer

    def get_queryset(self):
        return Booking.objects.filter(teacher=self.request.user).exclude(
            booking_status='pending'
        ).select_related(
            'student', 'subject', 'course'
        ).prefetch_related('schedules')


class CancelScheduleView(APIView):
    """Cancel an individual scheduled class. Available to the teacher or student of the booking."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request, pk):
        reason = request.data.get('reason', '').strip()
        if not reason:
            return Response({'error': 'A cancellation reason is required.'}, status=400)

        try:
            schedule = BookingSchedule.objects.select_related(
                'booking__teacher', 'booking__student', 'booking__subject', 'class_session'
            ).get(pk=pk)
        except BookingSchedule.DoesNotExist:
            return Response({'error': 'Schedule not found.'}, status=404)

        booking = schedule.booking
        user = request.user

        # Only the teacher or student of this booking can cancel
        if user.id != booking.teacher_id and user.id != booking.student_id:
            return Response({'error': 'You are not authorized to cancel this class.'}, status=403)

        if schedule.status != 'scheduled':
            return Response({'error': f'Cannot cancel a class that is already {schedule.status}.'}, status=400)

        # Cancel the schedule
        schedule.status = 'cancelled'
        schedule.cancel_reason = reason
        schedule.cancelled_by = user
        schedule.cancelled_at = timezone.now()
        schedule.save()

        # Also cancel the linked ClassSession if it exists
        if schedule.class_session and schedule.class_session.status == 'Scheduled':
            schedule.class_session.status = 'Cancelled'
            schedule.class_session.cancel_reason = reason
            schedule.class_session.cancelled_by = user
            schedule.class_session.save()

        # Send email notification to the other party
        self._send_cancel_notification(schedule, user)

        return Response({
            'message': 'Class cancelled successfully.',
            'schedule_id': schedule.id,
            'status': 'cancelled',
        })

    def _send_cancel_notification(self, schedule, cancelled_by_user):
        booking = schedule.booking
        is_teacher = cancelled_by_user.id == booking.teacher_id

        # Notify the OTHER party
        if is_teacher:
            recipient = booking.student
            canceller_role = 'Teacher'
            canceller_name = f"{booking.teacher.first_name} {booking.teacher.last_name}".strip()
        else:
            recipient = booking.teacher
            canceller_role = 'Student'
            canceller_name = f"{booking.student.first_name} {booking.student.last_name}".strip()

        date_str = schedule.date.strftime('%A, %b %d, %Y')
        time_str = schedule.start_time.strftime('%I:%M %p')

        subject_line = f"Class Cancelled: {booking.subject.name} on {date_str}"
        body = (
            f"Hello {recipient.first_name or 'User'},\n\n"
            f"A scheduled class has been cancelled.\n\n"
            f"Subject: {booking.subject.name}\n"
            f"Date: {date_str}\n"
            f"Time: {time_str}\n"
            f"Cancelled by: {canceller_name} ({canceller_role})\n"
            f"Reason: {schedule.cancel_reason}\n\n"
            f"If you have any concerns, please contact Produit Academy support.\n\n"
            f"Best regards,\nProduit Academy Team"
        )

        try:
            send_mail(subject_line, body, settings.DEFAULT_FROM_EMAIL, [recipient.email], fail_silently=False)
            EmailLog.objects.create(
                recipient_email=recipient.email, subject=subject_line,
                email_type='class_cancelled', status='sent', related_booking=booking,
            )
        except Exception as e:
            EmailLog.objects.create(
                recipient_email=recipient.email, subject=subject_line,
                email_type='class_cancelled', status='failed',
                error_message=str(e), related_booking=booking,
            )


class StudentCancelBookingView(APIView):
    """
    Cancel an entire confirmed booking and issue an automated Razorpay refund.
    Available to the student of the booking or platform staff.
    """
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request, pk):
        reason = request.data.get('reason', '').strip() or 'Cancelled by student'

        try:
            booking = Booking.objects.select_related('student', 'teacher', 'subject', 'course').get(pk=pk)
        except Booking.DoesNotExist:
            return Response({'error': 'Booking not found.'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        if user.id != booking.student_id and not (user.is_staff or user.is_superuser):
            return Response({'error': 'You are not authorized to cancel this booking.'}, status=status.HTTP_403_FORBIDDEN)

        if booking.booking_status not in ['pending', 'confirmed']:
            return Response({'error': f'Cannot cancel a booking that is already {booking.booking_status}.'}, status=status.HTTP_400_BAD_REQUEST)

        refund_id = None
        refund_amount = float(booking.total_amount)

        # If payment was made via Razorpay, trigger the refund
        if booking.payment_status in ['advance_paid', 'fully_paid'] and booking.razorpay_payment_id:
            try:
                client = get_razorpay_client()
                amount_in_paise = int(booking.total_amount * 100)
                refund_resp = client.payment.refund(booking.razorpay_payment_id, {
                    'amount': amount_in_paise,
                    'notes': {
                        'booking_id': str(booking.id),
                        'cancelled_by': user.email,
                        'reason': reason,
                    }
                })
                refund_id = refund_resp.get('id')

                # Log refund transaction
                PaymentTransaction.objects.create(
                    booking=booking,
                    user=user,
                    razorpay_order_id=booking.razorpay_order_id or '',
                    razorpay_payment_id=booking.razorpay_payment_id,
                    amount=booking.total_amount,
                    currency='INR',
                    status='failed',
                    error_description=f"Refund initiated: {refund_id}",
                    raw_response=refund_resp
                )
            except Exception as e:
                logger.error(f"Razorpay refund failed for booking {booking.id}: {e}", exc_info=True)
                return Response({
                    'error': f'Failed to process refund through payment gateway: {str(e)}. Please contact support.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Update booking status
        booking.booking_status = 'cancelled'
        if refund_id:
            booking.payment_status = 'refunded'
        booking.save()

        # Cancel all schedules
        now = timezone.now()
        booking.schedules.filter(status='scheduled').update(
            status='cancelled',
            cancel_reason=reason,
            cancelled_by=user,
            cancelled_at=now
        )

        # Cancel all linked sessions
        for schedule in booking.schedules.all():
            if schedule.class_session and schedule.class_session.status == 'Scheduled':
                schedule.class_session.status = 'Cancelled'
                schedule.class_session.cancel_reason = reason
                schedule.class_session.cancelled_by = user
                schedule.class_session.save()

        # Send cancellation emails to both student and teacher
        self._send_cancellation_emails(booking, reason, refund_amount if refund_id else 0)

        return Response({
            'message': 'Booking cancelled successfully. Refund has been initiated to your original payment method.',
            'booking_id': booking.id,
            'refund_id': refund_id,
            'refund_amount': refund_amount if refund_id else 0,
        }, status=status.HTTP_200_OK)

    def _send_cancellation_emails(self, booking, reason, refund_amount):
        student = booking.student
        teacher = booking.teacher

        student_subject = f"Booking Cancelled & Refund Initiated: {booking.subject.name}"
        student_body = (
            f"Hello {student.first_name or 'Student'},\n\n"
            f"Your booking for {booking.subject.name} with {teacher.first_name} {teacher.last_name} has been cancelled.\n\n"
            f"Reason: {reason}\n"
            f"Refund Amount: ₹{refund_amount}\n"
            f"Refund Status: Initiated via Razorpay (Usually takes 5-7 business days for bank processing, or instant for UPI).\n\n"
            f"If you have any questions, feel free to contact us.\n\n"
            f"Best regards,\nProduit Academy Team"
        )
        self._send_and_log(student.email, student_subject, student_body, 'booking_cancel_student', booking)

        teacher_subject = f"Booking Cancelled: {booking.subject.name} - {student.first_name} {student.last_name}"
        teacher_body = (
            f"Hello {teacher.first_name or 'Teacher'},\n\n"
            f"The booking for {booking.subject.name} with student {student.first_name} {student.last_name} has been cancelled.\n\n"
            f"Reason: {reason}\n"
            f"Your previously reserved time slots have now been freed up on your calendar for other students to book.\n\n"
            f"Best regards,\nProduit Academy Team"
        )
        self._send_and_log(teacher.email, teacher_subject, teacher_body, 'booking_cancel_teacher', booking)

    def _send_and_log(self, email, subject, body, email_type, booking):
        try:
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
            EmailLog.objects.create(
                recipient_email=email, subject=subject,
                email_type=email_type, status='sent', related_booking=booking,
            )
        except Exception as e:
            EmailLog.objects.create(
                recipient_email=email, subject=subject,
                email_type=email_type, status='failed',
                error_message=str(e), related_booking=booking,
            )


# ============================================================
# ADMIN ENDPOINTS
# ============================================================

def send_student_action_notification(student_email, student_name, action_type, reason=''):
    action_titles = {
        'delete': ('Account Removed - Produit Classes', 'Account Removed', 'Your student account has been removed by the administration.', '#e74c3c'),
        'hold': ('Account Placed on Hold - Produit Classes', 'Account Placed on Hold', 'Your student account has been temporarily placed on hold by the administration.', '#f39c12'),
        'ban': ('Account Suspended - Produit Classes', 'Account Suspended', 'Your student account has been suspended/banned by the administration.', '#c0392b'),
        'activate': ('Account Reactivated - Produit Classes', 'Account Reactivated', 'Your student account has been reactivated. You may now log in and attend your classes.', '#27ae60'),
    }
    email_type = f"student_{action_type}"
    subject, badge_text, intro_text, badge_color = action_titles.get(
        action_type,
        ('Account Status Update - Produit Classes', 'Status Update', 'Your account status has been updated.', '#3498db')
    )

    reason_html = ""
    reason_plain = ""
    if reason:
        reason_html = f"""
        <div style="margin: 20px 0; padding: 14px 18px; background-color: #f8fafc; border-left: 4px solid {badge_color}; border-radius: 4px;">
            <p style="margin: 0; font-size: 13px; color: #64748b; font-weight: 600; text-transform: uppercase;">Reason / Details:</p>
            <p style="margin: 6px 0 0; font-size: 15px; color: #1e293b;">{reason}</p>
        </div>
        """
        reason_plain = f"\n\nReason / Details:\n{reason}\n"

    cta_html = ""
    if action_type == 'activate':
        cta_html = """
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://classes.produitacademy.com/login" style="background-color: #27ae60; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 15px; display: inline-block;">Log In to Produit Classes</a>
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin: 0; padding: 20px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #334155; line-height: 1.6;">
        <div style="max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.06); border: 1px solid #e2e8f0;">
            <div style="background: #0f172a; padding: 24px 30px; text-align: center;">
                <h1 style="margin: 0; color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: 0.5px;">Produit Classes</h1>
                <p style="margin: 4px 0 0; color: #94a3b8; font-size: 13px;">Official Administration Notice</p>
            </div>
            <div style="padding: 30px;">
                <div style="display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: {badge_color}18; color: {badge_color}; margin-bottom: 16px;">
                    {badge_text}
                </div>
                <h2 style="margin: 0 0 16px; font-size: 19px; color: #0f172a;">Hello {student_name},</h2>
                <p style="margin: 0 0 16px; font-size: 15px;">{intro_text}</p>
                {reason_html}
                {cta_html}
                <p style="margin: 20px 0 0; font-size: 13px; color: #64748b;">
                    If you have any questions or require assistance, please contact the administration team at <a href="mailto:support@produitacademy.com" style="color: #2563eb; text-decoration: underline;">support@produitacademy.com</a>.
                </p>
            </div>
            <div style="background: #f8fafc; padding: 16px 30px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8;">
                &copy; {timezone.now().year} Produit Academy. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    plain_message = f"Hello {student_name},\n\n{intro_text}{reason_plain}\nIf you have any questions, please contact us at support@produitacademy.com.\n\nProduit Classes Team"

    from django.db import connection
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[student_email],
            html_message=html_content,
            fail_silently=True,
        )
        try:
            connection.close_if_unusable_or_obsolete()
            EmailLog.objects.create(
                recipient_email=student_email,
                subject=subject,
                email_type=email_type,
                status='sent',
            )
        except Exception:
            pass
    except Exception as e:
        try:
            connection.close_if_unusable_or_obsolete()
            EmailLog.objects.create(
                recipient_email=student_email,
                subject=subject,
                email_type=email_type,
                status='failed',
                error_message=str(e)[:500],
            )
        except Exception:
            pass


class AdminStudentsListView(generics.ListAPIView):
    """View-only list of registered students for admin."""
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        students = User.objects.filter(
            platform='classes', role='student'
        ).order_by('-date_joined')

        search = request.query_params.get('search', '').strip()
        if search:
            students = students.filter(
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search) |
                models.Q(email__icontains=search) |
                models.Q(phone_number__icontains=search)
            )

        data = [{
            'id': s.id,
            'name': f"{s.first_name} {s.last_name}".strip() or s.username,
            'email': s.email,
            'phone': s.phone_number or '',
            'registered': s.date_joined.isoformat(),
            'is_active': s.is_active,
            'account_status': getattr(s, 'account_status', 'active' if s.is_active else 'hold'),
            'status_reason': getattr(s, 'status_reason', '') or '',
        } for s in students[:100]]
        return Response(data)


class AdminStudentActionView(APIView):
    """
    Admin actions on a student: delete, hold, ban, activate.
    POST /api/classes/admin/students/<pk>/action/
    Body: { "action": "delete"|"hold"|"ban"|"activate", "reason": "optional note" }
    """
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk):
        from api.models import Session
        try:
            student = User.objects.get(pk=pk, role='student')
        except User.DoesNotExist:
            return Response({'error': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action', '').strip().lower()
        reason = request.data.get('reason', '').strip()
        student_email = student.email
        student_name = f"{student.first_name} {student.last_name}".strip() or student.username

        if action == 'delete':
            send_student_action_notification(student_email, student_name, 'delete', reason)
            student.delete()
            return Response({
                'message': f'Student {student_name} deleted successfully and confirmation email sent.',
                'action': 'delete',
            })

        elif action == 'hold':
            student.is_active = False
            student.account_status = 'hold'
            student.status_reason = reason
            student.save()
            Session.objects.filter(user=student).delete()
            send_student_action_notification(student_email, student_name, 'hold', reason)
            return Response({
                'message': f'Student {student_name} placed on hold and notification email sent.',
                'action': 'hold',
                'account_status': 'hold',
                'is_active': False,
                'status_reason': reason,
            })

        elif action in ['ban', 'reban']:
            student.is_active = False
            student.account_status = 'banned'
            student.status_reason = reason
            student.save()
            Session.objects.filter(user=student).delete()
            send_student_action_notification(student_email, student_name, 'ban', reason)
            return Response({
                'message': f'Student {student_name} banned and notification email sent.',
                'action': 'ban',
                'account_status': 'banned',
                'is_active': False,
                'status_reason': reason,
            })

        elif action in ['activate', 'unban']:
            student.is_active = True
            student.account_status = 'active'
            student.status_reason = ''
            student.save()
            send_student_action_notification(student_email, student_name, 'activate', reason)
            return Response({
                'message': f'Student {student_name} reactivated and notification email sent.',
                'action': 'activate',
                'account_status': 'active',
                'is_active': True,
                'status_reason': '',
            })

        else:
            return Response({
                'error': f'Invalid action "{action}". Valid actions are: delete, hold, ban, activate.'
            }, status=status.HTTP_400_BAD_REQUEST)


class AdminBookingsListView(generics.ListAPIView):
    """All bookings for admin view."""
    permission_classes = [permissions.IsAdminUser]
    serializer_class = BookingSerializer

    def get_queryset(self):
        return Booking.objects.all().select_related(
            'teacher', 'student', 'subject', 'course'
        ).prefetch_related('schedules').order_by('-created_at')


class AdminSubjectManageView(APIView):
    """Admin CRUD for subjects."""
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        course_id = request.query_params.get('course_id')
        qs = Subject.objects.all().select_related('course')
        if course_id:
            qs = qs.filter(course_id=course_id)
        return Response(SubjectSerializer(qs, many=True).data)

    def post(self, request):
        serializer = SubjectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)

    def delete(self, request):
        subject_id = request.data.get('subject_id')
        try:
            Subject.objects.get(pk=subject_id).delete()
            return Response({'message': 'Subject deleted.'})
        except Subject.DoesNotExist:
            return Response({'error': 'Subject not found.'}, status=404)
