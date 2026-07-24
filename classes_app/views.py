from django.utils import timezone
from django.db.models import Count, Q, Sum
from datetime import timedelta, datetime, time as dt_time, date as dt_date
import csv
import io
from django.core.mail import send_mail

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.exceptions import PermissionDenied

from api.models import User
from .models import Course, Enrollment, ClassSession, AttendanceRecord, TeacherAvailability
from .serializers import (
    CourseSerializer, EnrollmentSerializer, ClassSessionSerializer,
    AttendanceRecordSerializer, BulkAttendanceSerializer,
    RosterStudentSerializer, StudentDashboardSerializer,
    TeacherDashboardSerializer,
    AdminStatsSerializer, BulkEnrollSerializer,
    StaffCreateSerializer, BasicUserSerializer,
    StaffUpdateSerializer, UserUpdateSerializer,
    TeacherAvailabilitySerializer,
)


# --- Permission helpers ---

class IsTeacher(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == 'teacher' or request.user.is_staff or request.user.is_superuser
        )





class IsClassesPlatform(permissions.BasePermission):
    """Ensure user belongs to the classes platform (or is admin)."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_staff or request.user.is_superuser:
            return True
        return request.user.platform == 'classes'


def _is_staff_approved(user):
    """Check if a teacher is HR-approved."""
    if user.role == 'teacher':
        return getattr(getattr(user, 'classes_teacher_profile', None), 'is_approved', False)
    return False

# --- Profile Endpoint ---

class ClassesMeView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        user = request.user

        # Build per-course teacher list from Enrollments
        teachers_info = []
        if user.role == 'student':
            enrollments = Enrollment.objects.filter(student=user, teacher__isnull=False).select_related('teacher', 'course')
            for e in enrollments:
                t = e.teacher
                if _is_staff_approved(t):
                    teachers_info.append({
                        'id': t.id,
                        'name': f"{t.first_name} {t.last_name}".strip(),
                        'email': t.email,
                        'course_id': e.course.id,
                        'course_name': e.course.name,
                    })

        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': 'admin' if user.is_staff or user.is_superuser else user.role,
            'platform': user.platform,
            'phone_number': user.phone_number,
            'college': user.college,
            'assigned_teachers': teachers_info,
        })


# --- Student Dashboard ---

class StudentDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        user = request.user
        now = timezone.now()

        # Courses the student is enrolled in
        enrolled_course_ids = Enrollment.objects.filter(
            student=user
        ).values_list('course_id', flat=True)

        courses = Course.objects.filter(id__in=enrolled_course_ids, is_active=True)

        # Upcoming classes: only sessions explicitly assigned to this student
        upcoming = ClassSession.objects.filter(
            student=user,
            scheduled_time__gte=now,
            status='Scheduled'
        ).distinct().order_by('scheduled_time')[:10]

        # Completed demos awaiting student acceptance
        completed_demos = ClassSession.objects.filter(
            student=user, is_demo=True, status='Completed', demo_outcome='Pending'
        ).order_by('-scheduled_time')[:5]

        # Attendance stats
        records = AttendanceRecord.objects.filter(student=user)
        total = records.count()
        present = records.filter(status='Present').count()
        absent = records.filter(status='Absent').count()
        late = records.filter(status='Late').count()
        pct = round((present + late) / total * 100, 1) if total > 0 else 100.0

        # Per-course teacher info from enrollments
        teachers_info = []
        enrollments_with_teachers = Enrollment.objects.filter(
            student=user, teacher__isnull=False
        ).select_related('teacher', 'course')
        for e in enrollments_with_teachers:
            t = e.teacher
            if _is_staff_approved(t):
                teachers_info.append({
                    'id': t.id,
                    'name': f"{t.first_name} {t.last_name}".strip(),
                    'email': t.email,
                    'course_id': e.course.id,
                    'course_name': e.course.name,
                })

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'completed_demos': ClassSessionSerializer(completed_demos, many=True).data,
            'total_classes': total,
            'present_count': present,
            'absent_count': absent,
            'late_count': late,
            'attendance_percentage': pct,
            'courses': CourseSerializer(courses, many=True).data,
            'assigned_teachers': teachers_info,
        }
        return Response(data)

# --- Teacher Dashboard ---

class TeacherDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request):
        user = request.user
        now = timezone.now()

        # Students assigned to this teacher (via Enrollment)
        student_ids = Enrollment.objects.filter(
            teacher=user
        ).values_list('student_id', flat=True).distinct()
        assigned_students = User.objects.filter(
            id__in=student_ids, platform='classes', role='student'
        ).order_by('first_name')

        # Only courses this teacher is assigned to (via TeacherProfile subjects)
        from .models import TeacherProfile
        try:
            teacher_profile = TeacherProfile.objects.get(user=user)
            courses = teacher_profile.subjects.filter(is_active=True)
        except TeacherProfile.DoesNotExist:
            courses = Course.objects.none()

        # Upcoming scheduled classes
        upcoming = ClassSession.objects.filter(
            teacher=user,
            scheduled_time__gte=now,
            status='Scheduled'
        ).order_by('scheduled_time')[:10]

        # Classes completed but attendance not yet submitted
        pending = ClassSession.objects.filter(
            teacher=user,
            status='Completed'
        ).annotate(att_count=Count('attendance')).filter(att_count=0)

        # Stats
        total_held = ClassSession.objects.filter(
            teacher=user, status='Completed'
        ).count()

        total_minutes = ClassSession.objects.filter(
            teacher=user, status='Completed'
        ).aggregate(total=Sum('duration_minutes'))['total'] or 0
        total_hours = round(total_minutes / 60, 1)

        hourly_rate = 0
        try:
            hourly_rate = float(user.classes_teacher_profile.hourly_rate)
        except:
            pass
        total_earnings = round(total_hours * hourly_rate, 2)

        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_minutes = ClassSession.objects.filter(
            teacher=user, status='Completed', scheduled_time__gte=month_start
        ).aggregate(total=Sum('duration_minutes'))['total'] or 0
        this_month_earnings = round((month_minutes / 60) * hourly_rate, 2)

        # Student info for the list, including which courses they share with this teacher
        students_data = []
        for student in assigned_students:
            records = AttendanceRecord.objects.filter(student=student)
            total_records = records.count()
            attended = records.filter(status__in=['Present', 'Late']).count()
            pct = round(attended / total_records * 100, 1) if total_records > 0 else 100.0
            # Courses this teacher teaches this student (names + IDs)
            student_enrollments = Enrollment.objects.filter(
                student=student, teacher=user
            ).select_related('course')
            student_courses = [e.course.name for e in student_enrollments]
            student_course_ids = [e.course.id for e in student_enrollments]
            students_data.append({
                'id': student.id,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'email': student.email,
                'attendance_percentage': pct,
                'courses': student_courses,
                'course_ids': student_course_ids,
            })

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'pending_attendance': ClassSessionSerializer(pending, many=True).data,
            'total_classes_held': total_held,
            'total_hours_worked': total_hours,
            'hourly_rate': hourly_rate,
            'total_earnings': total_earnings,
            'this_month_earnings': this_month_earnings,
            'total_students': assigned_students.count(),
            'courses': CourseSerializer(courses, many=True).data,
            'assigned_students': students_data,
        }
        return Response(data)


# --- Session Create ---

class SessionCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def post(self, request):
        teacher = request.user
        if not _is_staff_approved(teacher):
            return Response({'error': 'Your profile is pending HR approval.'}, status=status.HTTP_403_FORBIDDEN)
            
        student_id = request.data.get('student_id') or request.data.get('student')
        course_id = request.data.get('course')
        scheduled_time = request.data.get('scheduled_time')
        duration_minutes = int(request.data.get('duration_minutes', 60))
        meeting_link = request.data.get('meeting_link', '')
        session_title = request.data.get('session_title', '')

        if not student_id or not course_id or not scheduled_time:
            return Response({'error': 'Student, course, and scheduled time are required.'}, status=400)

        try:
            course = Course.objects.get(id=course_id)
        except Course.DoesNotExist:
            return Response({'error': 'Course not found.'}, status=404)
            
        try:
            student = User.objects.get(id=student_id, role='student')
        except User.DoesNotExist:
            return Response({'error': 'Student not found.'}, status=404)

        is_assigned = Enrollment.objects.filter(
            student=student, course=course, teacher=teacher
        ).exists()
        
        if not is_assigned:
            return Response({'error': 'You are not assigned to teach this course to this student.'}, status=403)

        if not session_title:
            session_title = f"1-to-1 Class: {course.name}"

        try:
            from dateutil.parser import parse
            st_dt = parse(scheduled_time)
            end_dt = st_dt + timedelta(minutes=duration_minutes)
            
            teacher_overlap = ClassSession.objects.filter(
                teacher=teacher, status='Scheduled',
                scheduled_time__lt=end_dt,
                scheduled_time__gte=st_dt - timedelta(hours=4)
            )
            for sess in teacher_overlap:
                s_end = sess.scheduled_time + timedelta(minutes=sess.duration_minutes)
                if max(st_dt, sess.scheduled_time) < min(end_dt, s_end):
                    return Response({'error': 'You already have a session scheduled during this time.'}, status=400)
                    
            student_overlap = ClassSession.objects.filter(
                student=student, status='Scheduled',
                scheduled_time__lt=end_dt,
                scheduled_time__gte=st_dt - timedelta(hours=4)
            )
            for sess in student_overlap:
                s_end = sess.scheduled_time + timedelta(minutes=sess.duration_minutes)
                if max(st_dt, sess.scheduled_time) < min(end_dt, s_end):
                    return Response({'error': 'The student already has a session scheduled during this time.'}, status=400)
        except Exception:
            pass

        session = ClassSession.objects.create(
            teacher=teacher, student=student, course=course,
            session_title=session_title, scheduled_time=scheduled_time,
            duration_minutes=duration_minutes, meeting_link=meeting_link,
            status='Scheduled'
        )
        
        return Response(ClassSessionSerializer(session).data, status=201)


# --- Session Roster ---

class SessionRosterView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request, pk):
        try:
            session = ClassSession.objects.get(pk=pk)
        except ClassSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        if session.student:
            students = User.objects.filter(pk=session.student_id)
        else:
            students = User.objects.none()

        serializer = RosterStudentSerializer(
            students, many=True, context={'session_id': pk}
        )
        return Response(serializer.data)


# --- Bulk Attendance ---

class BulkAttendanceView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def post(self, request, pk):
        try:
            session = ClassSession.objects.get(pk=pk)
        except ClassSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = BulkAttendanceSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        records = serializer.validated_data['records']
        created = 0
        for item in records:
            AttendanceRecord.objects.update_or_create(
                class_session=session,
                student_id=item['student_id'],
                defaults={
                    'status': item['status'],
                    'marked_by': request.user,
                }
            )
            created += 1

        # Auto-mark session as Completed
        if session.status == 'Scheduled':
            session.status = 'Completed'
            session.save()

        return Response({
            'detail': f'Attendance saved for {created} students.',
            'session_status': session.status,
        })

# --- Mentor Dashboard (REMOVED) ---

# --- Admin Endpoints ---

class PublicCourseListView(generics.ListAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CourseSerializer

    def get_queryset(self):
        qs = Course.objects.filter(is_active=True).annotate(
            _student_count=Count('enrollments')
        ).order_by('name')
        search = self.request.query_params.get('search', '').strip()
        if search:
            qs = qs.filter(name__icontains=search)
        return qs

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page_size = int(request.query_params.get('page_size', 20))
        page_num = int(request.query_params.get('page', 1))

        total = queryset.count()
        start = (page_num - 1) * page_size
        end = start + page_size
        page_data = queryset[start:end]

        serializer = self.get_serializer(page_data, many=True)
        return Response({
            'results': serializer.data,
            'count': total,
            'page': page_num,
            'page_size': page_size,
            'has_next': end < total,
        })


class AdminCourseListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = CourseSerializer

    def get_queryset(self):
        qs = Course.objects.all().annotate(
            _student_count=Count('enrollments')
        ).order_by('-created_at')
        search = self.request.query_params.get('search', '').strip()
        if search:
            qs = qs.filter(name__icontains=search)
        return qs

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page_size = int(request.query_params.get('page_size', 20))
        page_num = int(request.query_params.get('page', 1))

        total = queryset.count()
        start = (page_num - 1) * page_size
        end = start + page_size
        page_data = queryset[start:end]

        serializer = self.get_serializer(page_data, many=True)
        return Response({
            'results': serializer.data,
            'count': total,
            'page': page_num,
            'page_size': page_size,
            'has_next': end < total,
        })


class AdminCourseDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Course.objects.all()
    serializer_class = CourseSerializer


class AdminBulkEnrollView(APIView):
    permission_classes = [permissions.IsAdminUser]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        teacher_id = request.data.get('teacher_id')

        teacher = None
        if teacher_id:
            try:
                teacher = User.objects.get(pk=teacher_id, role='teacher')
                if not _is_staff_approved(teacher):
                    return Response({'detail': 'Selected teacher is not approved.'}, status=400)
            except User.DoesNotExist:
                pass

        body = request.data

        course_id = body.get('course_id')
        email = body.get('email')

        # Extra profile fields
        first_name = body.get('first_name')
        last_name = body.get('last_name')
        phone = body.get('phone_number')
        address = body.get('address')
        current_class = body.get('current_class')
        school = body.get('school_name')

        if not course_id or not email:
            return Response({'detail': 'course_id and email are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            course = Course.objects.get(pk=course_id)
        except Course.DoesNotExist:
            return Response({'detail': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            student = User.objects.get(email=email)
            created_user = False
        except User.DoesNotExist:
            # Create student automatically
            password = phone if phone else "ProduitStudent123!" 
            student = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                role='student',
                platform='classes',
                is_active=True,
                is_verified=True
            )
            created_user = True

        _, created_enrollment = Enrollment.objects.get_or_create(
            student=student, course=course
        )

        # Assign teacher to enrollment if provided
        if teacher:
            enrollment = Enrollment.objects.filter(student=student, course=course).first()
            if enrollment and not enrollment.teacher:
                enrollment.teacher = teacher
                enrollment.save()

        # Update student profile fields if provided
        updated = False
        if first_name and not student.first_name:
            student.first_name = first_name
            updated = True
        if last_name and not student.last_name:
            student.last_name = last_name
            updated = True
        if phone and not student.phone_number:
            student.phone_number = phone
            updated = True
        if address and not student.address:
            student.address = address
            updated = True
        if current_class and not student.current_class:
            student.current_class = current_class
            updated = True
        if school and not student.school_name:
            student.school_name = school
            updated = True
        
        if updated:
            student.save()

        # Send enrollment email
        if created_enrollment:
            subject = f"You have been enrolled in {course.name}"
            message = f"Hello {student.first_name or 'Student'},\n\nYou have been successfully enrolled in the course '{course.name}' at Produit Academy.\n"
            if created_user:
                message += f"\nAn account has been created for you.\nYour login email is: {student.email}\nYour temporary password is: {phone if phone else 'ProduitStudent123!'}\n\nPlease log in at https://classes.produitacademy.com/login and change your password.\n"
            else:
                message += f"\nPlease log in at https://classes.produitacademy.com/login to view your new course.\n"
            message += "\nBest regards,\nProduit Academy Team"
            
            try:
                send_mail(
                    subject,
                    message,
                    'noreply@produitacademy.com',
                    [student.email],
                    fail_silently=True,
                )
            except Exception as e:
                print(f"Failed to send email: {e}")

            return Response({
                'detail': f'Student enrolled successfully. Email notification sent.',
            })
        else:
            return Response({
                'detail': f'Student is already enrolled in this course.',
            })


class AdminStatsView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        now = timezone.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        total_students = User.objects.filter(
            platform='classes', role='student'
        ).count()
        total_teachers = User.objects.filter(
            platform='classes', role='teacher'
        ).count()
        total_courses = Course.objects.filter(is_active=True).count()
        classes_month = ClassSession.objects.filter(
            scheduled_time__gte=month_start
        ).count()

        # Active students = students who have attended at least 1 class today
        active_today = AttendanceRecord.objects.filter(
            timestamp__gte=today_start,
            status__in=['Present', 'Late']
        ).values('student').distinct().count()

        # Overall attendance rate
        total_records = AttendanceRecord.objects.count()
        present_records = AttendanceRecord.objects.filter(
            status__in=['Present', 'Late']
        ).count()
        att_rate = round(present_records / total_records * 100, 1) if total_records > 0 else 0

        # Total bookings
        from .models import Booking
        total_bookings = Booking.objects.count()

        return Response({
            'total_students': total_students,
            'total_teachers': total_teachers,
            'total_courses': total_courses,
            'total_classes_this_month': classes_month,
            'active_students_today': active_today,
            'overall_attendance_rate': att_rate,
            'total_bookings': total_bookings,
        })


class AdminEnrollmentListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = EnrollmentSerializer

    def get_queryset(self):
        qs = Enrollment.objects.select_related(
            'student', 'course'
        ).all().order_by('-enrolled_at')
        course_id = self.request.query_params.get('course_id')
        if course_id:
            qs = qs.filter(course_id=course_id)
        return qs


# Student Personal Stats
class StudentStatsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        total_records = AttendanceRecord.objects.filter(student=user).count()
        attended = AttendanceRecord.objects.filter(student=user, status__in=['Present', 'Late']).count()
        percentage = round((attended / total_records * 100)) if total_records > 0 else 100

        return Response({
            "total_attended": attended,
            "attendance_percentage": percentage
        })


# --- Admin Staff Management ---

class AdminStaffManagementView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return StaffCreateSerializer
        return BasicUserSerializer

    def get_queryset(self):
        qs = User.objects.filter(platform='classes', role='teacher').order_by('-date_joined')
        if self.request.query_params.get('approved_only') == 'true':
            # Teachers with approved profiles
            qs = qs.filter(
                classes_teacher_profile__is_approved=True
            ).distinct()
        return qs

    def list(self, request, *args, **kwargs):
        """Override list to include subjects with names for teacher filtering."""
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data

        # Prefetch teacher subjects with names
        from .models import TeacherProfile
        teacher_subjects = {}
        for tp in TeacherProfile.objects.filter(
            user__in=queryset
        ).prefetch_related('subjects').select_related('user'):
            teacher_subjects[tp.user_id] = list(tp.subjects.values('id', 'name'))

        for item in data:
            uid = item['id']
            if uid in teacher_subjects:
                item['subjects_detail'] = teacher_subjects[uid]
            else:
                item['subjects_detail'] = []

        return Response(data)

    def perform_create(self, serializer):
        user = self.request.user
        is_admin = user.role == 'admin' or user.is_staff or user.is_superuser
        if not is_admin:
            raise PermissionDenied("Only administrators can create staff accounts.")
        serializer.save()


# --- Admin Assign Staff to Student ---

class AdminAssignStaffView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        student_id = request.data.get('student_id')
        teacher_id = request.data.get('teacher_id')
        course_id = request.data.get('course_id')  # Required for teacher assignment

        try:
            student = User.objects.get(pk=student_id, role='student')
        except User.DoesNotExist:
            return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

        student.save()

        # Teacher assignment is now per-course via Enrollment
        if teacher_id and course_id:
            try:
                teacher = User.objects.get(pk=teacher_id, role='teacher')
                if not _is_staff_approved(teacher):
                    return Response({'detail': 'Teacher is not approved.'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'detail': 'Teacher not found'}, status=status.HTTP_404_NOT_FOUND)
            enrollment = Enrollment.objects.filter(student=student, course_id=course_id).first()
            if enrollment:
                enrollment.teacher = teacher
                enrollment.save()
            else:
                return Response({'detail': 'Student is not enrolled in that course.'}, status=status.HTTP_400_BAD_REQUEST)
        elif teacher_id == '' and course_id:
            enrollment = Enrollment.objects.filter(student=student, course_id=course_id).first()
            if enrollment:
                enrollment.teacher = None
                enrollment.save()

        return Response({'detail': 'Staff assignment updated.'})


class AdminStaffDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = StaffUpdateSerializer

    def get_queryset(self):
        return User.objects.filter(platform='classes', role='teacher')


class AdminStudentDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = UserUpdateSerializer

    def get_queryset(self):
        return User.objects.filter(platform='classes')


class AdminEnrollmentToggleCompletionView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk):
        try:
            enrollment = Enrollment.objects.get(pk=pk)
            # Toggle logic
            enrollment.is_completed = not enrollment.is_completed
            enrollment.save()
            status_text = 'completed' if enrollment.is_completed else 'in progress'
            return Response({
                'detail': f'Enrollment marked as {status_text}.',
                'is_completed': enrollment.is_completed
            })
        except Enrollment.DoesNotExist:
            return Response({'detail': 'Enrollment not found.'}, status=status.HTTP_404_NOT_FOUND)

class AdminUserAnalyticsView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk, platform='classes')
        except User.DoesNotExist:
            return Response({'detail': 'User not found on this platform.'}, status=status.HTTP_404_NOT_FOUND)

        data = {
            'user': {
                'id': user.id,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email': user.email,
                'role': user.role,
                'phone': user.phone_number,
                'joined': user.date_joined,
            },
            'analytics': {}
        }

        if user.role == 'student':
            enrollments = Enrollment.objects.filter(student=user)
            completed_courses = enrollments.filter(is_completed=True).count()
            total_courses = enrollments.count()
            
            attendance = AttendanceRecord.objects.filter(student=user)
            total_classes = attendance.count()
            attended = attendance.filter(status='Present').count()
            attendance_rate = round((attended / total_classes * 100) if total_classes > 0 else 0, 1)

            recent_sessions = attendance.select_related('class_session', 'class_session__course').order_by('-timestamp')[:5]
            recent_data = [{
                'session_title': r.class_session.title,
                'course': r.class_session.course.name,
                'date': r.class_session.scheduled_time,
                'status': r.status
            } for r in recent_sessions]

            data['analytics'] = {
                'total_courses': total_courses,
                'completed_courses': completed_courses,
                'total_classes_recorded': total_classes,
                'attended_classes': attended,
                'attendance_rate': attendance_rate,
                'recent_sessions': recent_data
            }

            # Teachers are per-course, list them all
            teacher_enrollments = Enrollment.objects.filter(
                student=user, teacher__isnull=False
            ).select_related('teacher', 'course')
            data['user']['teachers'] = [
                {'name': f"{e.teacher.first_name} {e.teacher.last_name}".strip(), 'course': e.course.name}
                for e in teacher_enrollments
            ]

        elif user.role == 'teacher':
            sessions = ClassSession.objects.filter(teacher=user, status='Completed')
            classes_taught = sessions.count()
            total_minutes = sessions.aggregate(total=Sum('duration_minutes'))['total'] or 0
            
            # Avg attendance across all their sessions
            all_attendance = AttendanceRecord.objects.filter(class_session__teacher=user)
            total_records = all_attendance.count()
            present_records = all_attendance.filter(status='Present').count()
            avg_attendance_rate = round((present_records / total_records * 100) if total_records > 0 else 0, 1)

            try:
                profile = user.classes_teacher_profile
                hourly_rate = float(profile.hourly_rate)
                
                data['user']['bio'] = profile.bio
                data['user']['qualification'] = profile.qualification
                data['user']['experience'] = profile.experience
                data['user']['skills'] = profile.skills
                data['user']['certifications'] = profile.certifications
                data['user']['languages'] = profile.languages
                data['user']['teaching_style'] = profile.teaching_style
                data['user']['google_meet_link'] = profile.google_meet_link
                data['user']['profile_picture_base64'] = profile.profile_picture_base64
                data['user']['courses'] = [c.name for c in profile.subjects.all()]
                data['user']['taught_subjects'] = [s.name for s in profile.taught_subjects.all()]
            except Exception as e:
                hourly_rate = 0
            total_earnings = round((total_minutes / 60) * hourly_rate, 2)
            
            from django.utils import timezone
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_sessions = sessions.filter(scheduled_time__gte=month_start)
            month_minutes = month_sessions.aggregate(total=Sum('duration_minutes'))['total'] or 0
            this_month_earnings = round((month_minutes / 60) * hourly_rate, 2)

            student_breakdown = []
            for enrollment in Enrollment.objects.filter(teacher=user).select_related('student', 'course'):
                student_sessions = sessions.filter(
                    student=enrollment.student, course=enrollment.course
                )
                mins = student_sessions.aggregate(total=Sum('duration_minutes'))['total'] or 0
                hours = round(mins / 60, 1)
                earned = round(hours * hourly_rate, 2)
                student_breakdown.append({
                    'student_name': f"{enrollment.student.first_name} {enrollment.student.last_name}".strip(),
                    'course_name': enrollment.course.name,
                    'hours': hours,
                    'earned': earned,
                })

            data['analytics'] = {
                'classes_taught': classes_taught,
                'total_teaching_hours': round(total_minutes / 60, 1),
                'avg_student_attendance_rate': avg_attendance_rate,
                'hourly_rate': hourly_rate,
                'total_earnings': total_earnings,
                'this_month_earnings': this_month_earnings,
                'student_breakdown': student_breakdown,
            }



        return Response(data)


# ============================================================
# 1-TO-1 DEMO AND FLEXIBLE BOOKING
# ============================================================

from api.views import send_html_email
from .models import TeacherProfile, TeacherAvailability

class ScheduleDemoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role not in ['admin']:
            return Response({'error': 'Only admins can schedule demos.'}, status=403)
        student_id = request.data.get('student_id')
        teacher_id = request.data.get('teacher_id')
        course_id = request.data.get('course_id')
        scheduled_time = request.data.get('scheduled_time')

        try:
            student = User.objects.get(pk=student_id, role='student')
            teacher = User.objects.get(pk=teacher_id, role='teacher')
            course = Course.objects.get(pk=course_id)
            if not _is_staff_approved(teacher):
                return Response({'error': 'Teacher is not approved.'}, status=400)
        except (User.DoesNotExist, Course.DoesNotExist):
            return Response({'error': 'Invalid student, teacher, or course.'}, status=404)

        # A teacher can have multiple students — no restriction here.
        # But check for time conflict when actually booking (handled in BookSessionView).

        demo = ClassSession.objects.create(
            student=student,
            teacher=teacher,
            course=course,
            title=f"Demo: {course.name}",
            scheduled_time=scheduled_time,
            duration_minutes=30,
            is_demo=True,
        )

        try:
            send_html_email(
                subject='Action Required: Demo Link Needed',
                recipient_email=teacher.email,
                username=teacher.email.split('@')[0],
                type='demo_alert',
                student_name=student.first_name
            )
        except Exception:
            pass

        return Response({'message': 'Demo scheduled successfully.', 'demo_id': demo.id})


class TeacherDemoLinkView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def patch(self, request, pk):
        link = request.data.get('meeting_link')
        if not link:
            return Response({'error': 'meeting_link is required'}, status=400)

        try:
            demo = ClassSession.objects.get(pk=pk, teacher=request.user, is_demo=True)
            demo.meeting_link = link
            demo.save() # Signal will trigger Brevo email
            return Response({'message': 'Meeting link saved successfully.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Demo not found'}, status=404)


class AcceptDemoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            demo = ClassSession.objects.get(pk=pk, student=request.user, is_demo=True)
            if demo.status != 'Completed':
                return Response({'error': 'Demo is not completed yet.'}, status=400)
            
            # Teacher can have multiple students across courses — no restriction here.

            # Create enrollment
            enrollment, created = Enrollment.objects.get_or_create(
                student=request.user,
                course=demo.course,
                defaults={'teacher': demo.teacher}
            )
            
            if not created and not enrollment.teacher:
                enrollment.teacher = demo.teacher
                enrollment.save()
                
            demo.demo_outcome = 'Approved'
            demo.save()
                
            return Response({'message': 'Demo accepted and enrolled successfully.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Demo not found'}, status=404)


class RejectDemoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            demo = ClassSession.objects.get(pk=pk, student=request.user, is_demo=True)
            if demo.status != 'Completed':
                return Response({'error': 'Demo is not completed yet.'}, status=400)
            demo.demo_outcome = 'Rejected'
            demo.save()
            
            return Response({'message': 'Demo rejected. Your admin will assign a new teacher soon.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Demo not found'}, status=404)


class BookSessionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        course_id = request.data.get('course_id')
        scheduled_time = request.data.get('scheduled_time')
        duration = int(request.data.get('duration_minutes', 60))

        try:
            enrollment = Enrollment.objects.get(student=request.user, course_id=course_id)
            teacher = enrollment.teacher
            if not teacher:
                return Response({'error': 'No teacher assigned for this course.'}, status=400)
            if not _is_staff_approved(teacher):
                return Response({'error': 'Teacher is not approved.'}, status=400)

            # Parse the requested time
            from django.utils.dateparse import parse_datetime
            requested_dt = parse_datetime(scheduled_time)
            if not requested_dt:
                return Response({'error': 'Invalid scheduled_time format.'}, status=400)

            # Make timezone-aware if needed
            if timezone.is_naive(requested_dt):
                requested_dt = timezone.make_aware(requested_dt)

            requested_date = requested_dt.date()
            requested_time = requested_dt.time()
            requested_end = requested_dt + timedelta(minutes=duration)

            # Check teacher availability for that specific date and time
            matching_slot = TeacherAvailability.objects.filter(
                teacher=teacher,
                date=requested_date,
                start_time__lte=requested_time,
                end_time__gte=requested_time
            ).first()

            if not matching_slot:
                return Response({
                    'error': 'The selected time is outside your teacher\'s available hours. Please choose a time within their schedule.'
                }, status=400)

            # 1-on-1 overlap prevention: check if teacher already has a session at this time
            overlapping = ClassSession.objects.filter(
                teacher=teacher,
                status='Scheduled',
                scheduled_time__lt=requested_end,
            ).exclude(
                # Exclude sessions that end before our start
                scheduled_time__lte=requested_dt - timedelta(minutes=1)
            )
            # More precise: also consider the session's own duration
            for existing in overlapping:
                existing_end = existing.scheduled_time + timedelta(minutes=existing.duration_minutes)
                if requested_dt < existing_end and requested_end > existing.scheduled_time:
                    return Response({
                        'error': 'This teacher is already booked at this time with another student. Please choose a different slot.'
                    }, status=400)

            session = ClassSession.objects.create(
                student=request.user,
                teacher=teacher,
                course=enrollment.course,
                title=f"1-to-1 Class: {enrollment.course.name}",
                scheduled_time=requested_dt,
                duration_minutes=duration,
                is_demo=False
            )
            return Response({'message': 'Session booked successfully.', 'session_id': session.id})
        except Enrollment.DoesNotExist:
            return Response({'error': 'Not enrolled in this course.'}, status=400)


class CompleteSessionView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def patch(self, request, pk):
        notes = request.data.get('teacher_notes', '')
        try:
            session = ClassSession.objects.get(pk=pk, teacher=request.user)
            session.status = 'Completed'
            session.teacher_notes = notes
            session.save()
            return Response({'message': 'Session marked as completed.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Session not found'}, status=404)


# ============================================================
# TEACHER AVAILABILITY & CANCELLATION
# ============================================================

def _get_next_week_range():
    """Return (monday, sunday) of the NEXT week from today."""
    today = dt_date.today()
    # Monday of next week
    days_until_next_monday = (7 - today.weekday()) % 7
    if days_until_next_monday == 0:
        days_until_next_monday = 7
    next_monday = today + timedelta(days=days_until_next_monday)
    next_sunday = next_monday + timedelta(days=6)
    return next_monday, next_sunday


def _is_past_sunday_deadline():
    """Check if we are past Sunday 6:00 PM (IST / server local time)."""
    now = timezone.localtime(timezone.now())
    # Sunday = weekday 6
    if now.weekday() == 6 and now.hour >= 18:
        return True
    return False


class TeacherAvailabilityView(APIView):
    """
    GET: Returns the teacher's availability slots for the upcoming week.
    POST: Submit availability slots for the upcoming week (blocked after Sunday 6 PM).
    """
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request):
        next_monday, next_sunday = _get_next_week_range()
        # Also include current week availability
        today = dt_date.today()
        current_monday = today - timedelta(days=today.weekday())
        current_sunday = current_monday + timedelta(days=6)

        slots = TeacherAvailability.objects.filter(
            teacher=request.user,
            date__gte=current_monday,
            date__lte=next_sunday
        )
        serializer = TeacherAvailabilitySerializer(slots, many=True)

        return Response({
            'slots': serializer.data,
            'current_week': {'start': str(current_monday), 'end': str(current_sunday)},
            'next_week': {'start': str(next_monday), 'end': str(next_sunday)},
            'deadline_passed': _is_past_sunday_deadline(),
        })

    def post(self, request):
        if _is_past_sunday_deadline():
            return Response({
                'error': 'The deadline has passed. You can only submit availability before Sunday 6:00 PM.'
            }, status=400)

        next_monday, next_sunday = _get_next_week_range()
        slots_data = request.data.get('slots', [])

        if not slots_data:
            return Response({'error': 'No slots provided.'}, status=400)

        created = 0
        updated = 0
        errors = []
        for slot in slots_data:
            slot_date = slot.get('date')
            start_time = slot.get('start_time')
            end_time = slot.get('end_time')

            if not all([slot_date, start_time, end_time]):
                errors.append(f'Missing fields in slot: {slot}')
                continue

            try:
                parsed_date = dt_date.fromisoformat(slot_date)
            except (ValueError, TypeError):
                errors.append(f'Invalid date: {slot_date}')
                continue

            if parsed_date < next_monday or parsed_date > next_sunday:
                errors.append(f'Date {slot_date} is not in next week ({next_monday} to {next_sunday}).')
                continue

            obj, was_created = TeacherAvailability.objects.update_or_create(
                teacher=request.user,
                date=parsed_date,
                start_time=start_time,
                defaults={'end_time': end_time}
            )
            if was_created:
                created += 1
            else:
                updated += 1

        total = created + updated
        return Response({
            'message': f'{total} slot(s) saved successfully ({created} new, {updated} updated).',
            'errors': errors if errors else None,
        })

    def delete(self, request):
        """Delete a specific availability slot."""
        slot_id = request.data.get('slot_id')
        if not slot_id:
            return Response({'error': 'slot_id is required.'}, status=400)
        try:
            slot = TeacherAvailability.objects.get(pk=slot_id, teacher=request.user)
            slot.delete()
            return Response({'message': 'Slot deleted.'})
        except TeacherAvailability.DoesNotExist:
            return Response({'error': 'Slot not found.'}, status=404)


class StudentTeacherSlotsView(APIView):
    """Student fetches their teacher's available slots for a specific course."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        course_id = request.query_params.get('course_id')
        if not course_id:
            return Response({'slots': [], 'message': 'Please provide a course_id.'})

        enrollment = Enrollment.objects.filter(
            student=request.user, course_id=course_id
        ).select_related('teacher').first()

        if not enrollment or not enrollment.teacher:
            return Response({'slots': [], 'message': 'No teacher assigned for this course yet.'})

        teacher = enrollment.teacher
        today = dt_date.today()

        # Get all availability slots from today onwards
        slots = TeacherAvailability.objects.filter(
            teacher=teacher,
            date__gte=today
        )

        # Subtract times already booked by ANY student with this teacher
        booked_sessions = ClassSession.objects.filter(
            teacher=teacher,
            status='Scheduled',
            scheduled_time__date__gte=today
        )
        booked_ranges = []
        for s in booked_sessions:
            booked_ranges.append({
                'date': s.scheduled_time.date(),
                'start': s.scheduled_time.time(),
                'end': (s.scheduled_time + timedelta(minutes=s.duration_minutes)).time(),
            })

        serializer = TeacherAvailabilitySerializer(slots, many=True)
        return Response({
            'teacher_name': f"{teacher.first_name} {teacher.last_name}".strip() or teacher.username,
            'slots': serializer.data,
            'booked_ranges': booked_ranges,
        })


class CancelSessionView(APIView):
    """Cancel a scheduled session with a reason. Notifies the teacher via email."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        reason = request.data.get('reason', '').strip()
        if not reason:
            return Response({'error': 'A cancellation reason is required.'}, status=400)

        try:
            # Allow teacher or student to cancel their own session
            session = ClassSession.objects.get(pk=pk, status='Scheduled')
            user = request.user

            # Verify the user is the teacher or student of this session
            if session.teacher != user and session.student != user:
                return Response({'error': 'You are not authorized to cancel this session.'}, status=403)

            session.status = 'Cancelled'
            session.cancel_reason = reason
            session.cancelled_by = user
            session.save()

            # Notify the session's teacher via email if student cancels
            teacher = session.teacher
            if teacher:
                canceller_role = 'Teacher' if user == session.teacher else 'Student'
                if canceller_role == 'Student':
                    try:
                        send_mail(
                            subject=f'Class Cancelled: {session.title}',
                            message=(
                                f"Hello {teacher.first_name or 'Teacher'},\n\n"
                                f"A class has been cancelled by the student:\n\n"
                                f"Class: {session.title}\n"
                                f"Course: {session.course.name}\n"
                                f"Scheduled Time: {session.scheduled_time}\n"
                                f"Reason: {reason}\n\n"
                                f"— Produit Academy"
                            ),
                            from_email='noreply@produitacademy.com',
                            recipient_list=[teacher.email],
                            fail_silently=True,
                        )
                    except Exception as e:
                        print(f"Failed to send cancellation email: {e}")

            return Response({'message': 'Session cancelled successfully.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Scheduled session not found.'}, status=404)

# ============================================================
# PROFILE & PASSWORD MANAGEMENT
# ============================================================

class ClassesProfileView(APIView):
    """View and update own profile for any classes platform user."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        user = request.user
        data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': user.phone_number or '',
            'role': 'admin' if user.is_staff or user.is_superuser else user.role,
            'platform': user.platform,
            'college': user.college or '',
            'address': user.address or '',
            'current_class': user.current_class or '',
            'school_name': user.school_name or '',
            'date_joined': user.date_joined.isoformat(),
        }

        # Add role-specific info
        if user.role == 'teacher':
            from .models import TeacherProfile
            try:
                tp = TeacherProfile.objects.get(user=user)
                data['subjects'] = list(tp.subjects.filter(is_active=True).values('id', 'name'))
            except TeacherProfile.DoesNotExist:
                data['subjects'] = []
        elif user.role == 'student':
            enrollments = Enrollment.objects.filter(student=user).select_related('course', 'teacher')
            data['courses'] = [
                {
                    'id': e.course.id,
                    'name': e.course.name,
                    'is_completed': e.is_completed,
                    'teacher': {
                        'id': e.teacher.id,
                        'name': f"{e.teacher.first_name} {e.teacher.last_name}".strip(),
                        'email': e.teacher.email
                    } if (e.teacher and _is_staff_approved(e.teacher)) else None
                }
                for e in enrollments
            ]


        return Response(data)

    def patch(self, request):
        user = request.user
        allowed_fields = ['first_name', 'last_name', 'phone_number', 'college', 'address', 'current_class', 'school_name']
        for field in allowed_fields:
            if field in request.data:
                setattr(user, field, request.data[field])
        user.save()
        
        # Generate new token with updated claims (e.g. first_name)
        from api.serializers import MyTokenObtainPairSerializer
        refresh = MyTokenObtainPairSerializer.get_token(user)
        
        return Response({
            'message': 'Profile updated successfully.',
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        })

class ClassesChangePasswordView(APIView):
    """Change password for any authenticated classes user."""
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def post(self, request):
        user = request.user
        current = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not current or not new_password:
            return Response({'error': 'Both current_password and new_password are required.'}, status=400)

        if not user.check_password(current):
            return Response({'error': 'Current password is incorrect.'}, status=400)

        if len(new_password) < 8:
            return Response({'error': 'New password must be at least 8 characters.'}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password changed successfully.'})

