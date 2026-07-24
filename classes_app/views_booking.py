"""
New views for course browsing flow, teacher profiles, booking, and payment.
"""
from datetime import timedelta, date as dt_date
from decimal import Decimal

from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import permissions, status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from api.models import User
from .models import (
    Course, Subject, TeacherProfile, TeacherAvailability,
    TeacherDemoVideo, Booking, BookingSchedule, ClassSession,
    Enrollment, EmailLog, PLATFORM_FEE,
)
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
        qs = Subject.objects.filter(is_active=True)
        if course_id:
            qs = qs.filter(course_id=course_id)
        return qs.select_related('course')


class TeachersBySubjectView(APIView):
    """List approved teachers for a given subject."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        subject_id = request.query_params.get('subject_id')
        if not subject_id:
            return Response({'error': 'subject_id is required'}, status=400)

        profiles = TeacherProfile.objects.filter(
            is_approved=True,
            taught_subjects__id=subject_id
        ).select_related('user')

        serializer = TeacherProfileCardSerializer(
            profiles, many=True,
            context={'request': request, 'subject_id': int(subject_id)}
        )
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
    """Payment history for student."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        bookings = Booking.objects.filter(student=request.user).exclude(
            booking_status='pending'
        ).order_by('-created_at')
        data = [{
            'id': b.id,
            'subject': b.subject.name,
            'teacher': f"{b.teacher.first_name} {b.teacher.last_name}".strip(),
            'total_amount': float(b.total_amount),
            'advance_paid': float(b.advance_amount),
            'remaining': float(b.remaining_amount),
            'payment_status': b.payment_status,
            'booking_status': b.booking_status,
            'date': b.created_at.isoformat(),
        } for b in bookings]
        return Response(data)


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


# ============================================================
# ADMIN ENDPOINTS
# ============================================================

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
        } for s in students[:100]]
        return Response(data)


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
