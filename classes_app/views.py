from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import csv
import io

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser

from api.models import User
from .models import Course, Enrollment, ClassSession, AttendanceRecord
from .serializers import (
    CourseSerializer, EnrollmentSerializer, ClassSessionSerializer,
    AttendanceRecordSerializer, BulkAttendanceSerializer,
    RosterStudentSerializer, StudentDashboardSerializer,
    TeacherDashboardSerializer, MentorDashboardSerializer,
    AdminStatsSerializer, BulkEnrollSerializer,
)


# --- Permission helpers ---

class IsTeacher(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == 'teacher' or request.user.is_staff or request.user.is_superuser
        )


class IsMentor(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == 'mentor' or request.user.is_staff or request.user.is_superuser
        )


class IsClassesPlatform(permissions.BasePermission):
    """Ensure user belongs to the classes platform (or is admin)."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_staff or request.user.is_superuser:
            return True
        return request.user.platform == 'classes'


# --- Profile Endpoint ---

class ClassesMeView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsClassesPlatform]

    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': 'admin' if user.is_staff or user.is_superuser else user.role,
            'platform': user.platform,
            'phone_number': user.phone_number,
            'college': user.college,
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

        # Upcoming classes (scheduled, in the future)
        upcoming = ClassSession.objects.filter(
            course_id__in=enrolled_course_ids,
            scheduled_time__gte=now,
            status='Scheduled'
        ).order_by('scheduled_time')[:10]

        # Attendance stats
        records = AttendanceRecord.objects.filter(student=user)
        total = records.count()
        present = records.filter(status='Present').count()
        absent = records.filter(status='Absent').count()
        late = records.filter(status='Late').count()
        pct = round((present + late) / total * 100, 1) if total > 0 else 100.0

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'total_classes': total,
            'present_count': present,
            'absent_count': absent,
            'late_count': late,
            'attendance_percentage': pct,
            'courses': CourseSerializer(courses, many=True).data,
        }
        return Response(data)


# --- Teacher Dashboard ---

class TeacherDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request):
        user = request.user
        now = timezone.now()

        courses = Course.objects.filter(teachers=user, is_active=True)
        course_ids = courses.values_list('id', flat=True)

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

        total_students = Enrollment.objects.filter(
            course_id__in=course_ids
        ).values('student').distinct().count()

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'pending_attendance': ClassSessionSerializer(pending, many=True).data,
            'total_classes_held': total_held,
            'total_students': total_students,
            'courses': CourseSerializer(courses, many=True).data,
        }
        return Response(data)


# --- Session Create ---

class SessionCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]
    serializer_class = ClassSessionSerializer

    def perform_create(self, serializer):
        serializer.save(teacher=self.request.user)


# --- Session Roster ---

class SessionRosterView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request, pk):
        try:
            session = ClassSession.objects.get(pk=pk)
        except ClassSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        students = User.objects.filter(
            classes_enrollments__course=session.course
        ).order_by('username')

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


# --- Mentor Dashboard ---

class MentorDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsMentor]

    def get(self, request):
        user = request.user
        now = timezone.now()
        week_ago = now - timedelta(days=7)

        # Courses this mentor oversees
        courses = Course.objects.filter(mentor=user, is_active=True)
        course_ids = courses.values_list('id', flat=True)

        # Teacher compliance
        teacher_compliance = []
        for course in courses:
            for teacher in course.teachers.all():
                sessions = ClassSession.objects.filter(
                    course=course, teacher=teacher
                )
                total = sessions.count()
                marked = sessions.filter(attendance__isnull=False).distinct().count()
                teacher_compliance.append({
                    'id': teacher.id,
                    'username': teacher.username,
                    'email': teacher.email,
                    'total_sessions': total,
                    'attendance_marked': marked,
                    'attendance_pending': total - marked,
                    'course_name': course.name,
                })

        # At risk students (attendance < 75%)
        at_risk = []
        enrollments = Enrollment.objects.filter(course_id__in=course_ids)
        for enrollment in enrollments:
            total_sessions = ClassSession.objects.filter(
                course=enrollment.course, status='Completed'
            ).count()
            if total_sessions == 0:
                continue
            attended = AttendanceRecord.objects.filter(
                student=enrollment.student,
                class_session__course=enrollment.course,
                status__in=['Present', 'Late']
            ).count()
            pct = round(attended / total_sessions * 100, 1)
            if pct < 75:
                at_risk.append({
                    'id': enrollment.student.id,
                    'username': enrollment.student.username,
                    'email': enrollment.student.email,
                    'phone_number': enrollment.student.phone_number,
                    'attendance_percentage': pct,
                    'total_classes': total_sessions,
                    'attended': attended,
                    'course_name': enrollment.course.name,
                    'course_id': enrollment.course.id,
                })

        # Sort at-risk by lowest attendance first
        at_risk.sort(key=lambda x: x['attendance_percentage'])

        classes_this_week = ClassSession.objects.filter(
            course_id__in=course_ids,
            scheduled_time__gte=week_ago
        ).count()

        total_students = enrollments.values('student').distinct().count()

        data = {
            'courses': CourseSerializer(courses, many=True).data,
            'at_risk_students': at_risk,
            'teacher_compliance': teacher_compliance,
            'total_classes_this_week': classes_this_week,
            'total_students': total_students,
        }
        return Response(data)


# --- Admin Endpoints ---

class PublicCourseListView(generics.ListAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CourseSerializer

    def get_queryset(self):
        return Course.objects.filter(is_active=True).order_by('name')


class AdminCourseListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Course.objects.all().order_by('-created_at')
    serializer_class = CourseSerializer


class AdminCourseDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Course.objects.all()
    serializer_class = CourseSerializer


class AdminBulkEnrollView(APIView):
    permission_classes = [permissions.IsAdminUser]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        # Support both JSON body and CSV file upload
        csv_file = request.FILES.get('file')

        if csv_file:
            # CSV file upload
            course_id = request.data.get('course_id')
            if not course_id:
                return Response({'detail': 'course_id is required'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                course = Course.objects.get(pk=course_id)
            except Course.DoesNotExist:
                return Response({'detail': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)

            decoded = csv_file.read().decode('utf-8')
            reader = csv.reader(io.StringIO(decoded))
            enrolled = 0
            errors = []

            for row in reader:
                if not row:
                    continue
                email = row[0].strip()
                try:
                    student = User.objects.get(email=email)
                    _, created = Enrollment.objects.get_or_create(
                        student=student, course=course
                    )
                    if created:
                        enrolled += 1
                except User.DoesNotExist:
                    errors.append(f"User not found: {email}")

            return Response({
                'detail': f'Enrolled {enrolled} students.',
                'errors': errors,
            })
        else:
            # JSON body
            serializer = BulkEnrollSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                course = Course.objects.get(pk=serializer.validated_data['course_id'])
            except Course.DoesNotExist:
                return Response({'detail': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)

            enrolled = 0
            errors = []
            for email in serializer.validated_data['student_emails']:
                try:
                    student = User.objects.get(email=email)
                    _, created = Enrollment.objects.get_or_create(
                        student=student, course=course
                    )
                    if created:
                        enrolled += 1
                except User.DoesNotExist:
                    errors.append(f"User not found: {email}")

            return Response({
                'detail': f'Enrolled {enrolled} students.',
                'errors': errors,
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
        total_mentors = User.objects.filter(
            platform='classes', role='mentor'
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

        return Response({
            'total_students': total_students,
            'total_teachers': total_teachers,
            'total_mentors': total_mentors,
            'total_courses': total_courses,
            'total_classes_this_month': classes_month,
            'active_students_today': active_today,
            'overall_attendance_rate': att_rate,
        })


class AdminEnrollmentListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = EnrollmentSerializer

    def get_queryset(self):
        qs = Enrollment.objects.all().order_by('-enrolled_at')
        course_id = self.request.query_params.get('course_id')
        if course_id:
            qs = qs.filter(course_id=course_id)
        return qs
