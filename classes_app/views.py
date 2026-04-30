from django.utils import timezone
from django.db.models import Count, Q, Sum
from datetime import timedelta
import csv
import io

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.exceptions import PermissionDenied

from api.models import User
from .models import Course, Enrollment, ClassSession, AttendanceRecord
from .serializers import (
    CourseSerializer, EnrollmentSerializer, ClassSessionSerializer,
    AttendanceRecordSerializer, BulkAttendanceSerializer,
    RosterStudentSerializer, StudentDashboardSerializer,
    TeacherDashboardSerializer,
    AdminStatsSerializer, BulkEnrollSerializer,
    StaffCreateSerializer, BasicUserSerializer,
    StaffUpdateSerializer, UserUpdateSerializer,
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
        mentor_info = None
        teacher_info = None
        if user.assigned_mentor:
            m = user.assigned_mentor
            mentor_info = {'id': m.id, 'name': f"{m.first_name} {m.last_name}", 'email': m.email}
        if user.assigned_teacher:
            t = user.assigned_teacher
            teacher_info = {'id': t.id, 'name': f"{t.first_name} {t.last_name}", 'email': t.email}

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
            'assigned_mentor': mentor_info,
            'assigned_teacher': teacher_info,
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

        # Upcoming classes: enrolled courses OR demos assigned directly to this student
        upcoming = ClassSession.objects.filter(
            Q(course_id__in=enrolled_course_ids) | Q(student=user),
            scheduled_time__gte=now,
            status='Scheduled'
        ).distinct().order_by('scheduled_time')[:10]

        # Completed demos awaiting student acceptance (not yet enrolled)
        completed_demos = ClassSession.objects.filter(
            student=user, is_demo=True, status='Completed'
        ).exclude(
            course_id__in=enrolled_course_ids
        ).order_by('-scheduled_time')[:5]

        # Attendance stats
        records = AttendanceRecord.objects.filter(student=user)
        total = records.count()
        present = records.filter(status='Present').count()
        absent = records.filter(status='Absent').count()
        late = records.filter(status='Late').count()
        pct = round((present + late) / total * 100, 1) if total > 0 else 100.0

        # Assigned staff info
        mentor_info = None
        teacher_info = None
        if user.assigned_mentor:
            m = user.assigned_mentor
            mentor_info = {'id': m.id, 'name': f"{m.first_name} {m.last_name}", 'email': m.email}
        if user.assigned_teacher:
            t = user.assigned_teacher
            teacher_info = {'id': t.id, 'name': f"{t.first_name} {t.last_name}", 'email': t.email}

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'completed_demos': ClassSessionSerializer(completed_demos, many=True).data,
            'total_classes': total,
            'present_count': present,
            'absent_count': absent,
            'late_count': late,
            'attendance_percentage': pct,
            'courses': CourseSerializer(courses, many=True).data,
            'assigned_mentor': mentor_info,
            'assigned_teacher': teacher_info,
        }
        return Response(data)


# --- Teacher Dashboard ---

class TeacherDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def get(self, request):
        user = request.user
        now = timezone.now()

        # Students assigned to this teacher
        assigned_students = User.objects.filter(
            assigned_teacher=user, platform='classes', role='student'
        ).order_by('first_name')

        # All active courses for dropdowns
        courses = Course.objects.filter(is_active=True)

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

        # Student info for the list
        students_data = []
        for student in assigned_students:
            records = AttendanceRecord.objects.filter(student=student)
            total_records = records.count()
            attended = records.filter(status__in=['Present', 'Late']).count()
            pct = round(attended / total_records * 100, 1) if total_records > 0 else 100.0
            students_data.append({
                'id': student.id,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'email': student.email,
                'attendance_percentage': pct,
            })

        data = {
            'upcoming_classes': ClassSessionSerializer(upcoming, many=True).data,
            'pending_attendance': ClassSessionSerializer(pending, many=True).data,
            'total_classes_held': total_held,
            'total_students': assigned_students.count(),
            'courses': CourseSerializer(courses, many=True).data,
            'assigned_students': students_data,
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

        # Students assigned to this mentor
        assigned_students = User.objects.filter(
            assigned_mentor=user, platform='classes', role='student'
        )

        # All students data with attendance
        all_students = []
        at_risk = []
        for student in assigned_students:
            records = AttendanceRecord.objects.filter(student=student)
            total = records.count()
            attended = records.filter(status__in=['Present', 'Late']).count()
            pct = round(attended / total * 100, 1) if total > 0 else 100.0

            student_info = {
                'id': student.id,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'email': student.email,
                'phone_number': student.phone_number,
                'attendance_percentage': pct,
                'total_classes': total,
                'attended': attended,
            }
            all_students.append(student_info)
            if pct < 75 and total > 0:
                at_risk.append(student_info)

        # Sort at-risk by lowest attendance first
        at_risk.sort(key=lambda x: x['attendance_percentage'])

        data = {
            'total_students': assigned_students.count(),
            'at_risk_students': at_risk,
            'all_students': all_students,
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
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        # Support both JSON body and CSV file upload
        csv_file = request.FILES.get('file')

        # Optional staff assignment
        mentor_id = request.data.get('mentor_id')
        teacher_id = request.data.get('teacher_id')

        mentor = None
        teacher = None
        if mentor_id:
            try:
                mentor = User.objects.get(pk=mentor_id, role='mentor')
            except User.DoesNotExist:
                pass
        if teacher_id:
            try:
                teacher = User.objects.get(pk=teacher_id, role='teacher')
            except User.DoesNotExist:
                pass

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
                if not email or email.lower() == 'email':
                    continue  # Skip header row if present
                
                # Extract optional fields if they exist in the CSV
                first_name = row[1].strip() if len(row) > 1 else None
                last_name = row[2].strip() if len(row) > 2 else None
                phone = row[3].strip() if len(row) > 3 else None
                address = row[4].strip() if len(row) > 4 else None
                current_class = row[5].strip() if len(row) > 5 else None
                school = row[6].strip() if len(row) > 6 else None

                try:
                    student = User.objects.get(email=email)
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

                _, created = Enrollment.objects.get_or_create(
                    student=student, course=course
                )
                
                # Update student profile fields
                updated = False
                if mentor and not student.assigned_mentor:
                    student.assigned_mentor = mentor
                    updated = True
                if teacher and not student.assigned_teacher:
                    student.assigned_teacher = teacher
                    updated = True
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
                    
                if created:
                    enrolled += 1

            return Response({
                'detail': f'Enrolled {enrolled} students.',
                'errors': errors,
            })
        else:
            # JSON body — supports single email or list
            body = request.data

            course_id = body.get('course_id')
            email = body.get('email')  # Single email for manual enroll
            student_emails = body.get('student_emails', [])  # Bulk list

            # Extra profile fields (for single manual enroll)
            extra_first_name = body.get('first_name')
            extra_last_name = body.get('last_name')
            extra_phone = body.get('phone_number')
            extra_address = body.get('address')
            extra_class = body.get('current_class')
            extra_school = body.get('school_name')

            if email:
                student_emails = [email]

            if not course_id or not student_emails:
                return Response({'detail': 'course_id and email(s) are required'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                course = Course.objects.get(pk=course_id)
            except Course.DoesNotExist:
                return Response({'detail': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)

            enrolled = 0
            errors = []
            for em in student_emails:
                try:
                    student = User.objects.get(email=em)
                except User.DoesNotExist:
                    # Create student automatically
                    password = extra_phone if extra_phone else "ProduitStudent123!" 
                    student = User.objects.create_user(
                        username=em,
                        email=em,
                        password=password,
                        role='student',
                        platform='classes',
                        is_active=True,
                        is_verified=True
                    )
                
                _, created = Enrollment.objects.get_or_create(
                    student=student, course=course
                )
                # Update student profile fields if provided
                updated = False
                if mentor and not student.assigned_mentor:
                    student.assigned_mentor = mentor
                    updated = True
                if teacher and not student.assigned_teacher:
                    student.assigned_teacher = teacher
                    updated = True
                if extra_first_name and not student.first_name:
                    student.first_name = extra_first_name
                    updated = True
                if extra_last_name and not student.last_name:
                    student.last_name = extra_last_name
                    updated = True
                if extra_phone and not student.phone_number:
                    student.phone_number = extra_phone
                    updated = True
                if extra_address and not student.address:
                    student.address = extra_address
                    updated = True
                if extra_class and not student.current_class:
                    student.current_class = extra_class
                    updated = True
                if extra_school and not student.school_name:
                    student.school_name = extra_school
                    updated = True
                if updated:
                    student.save()
                if created:
                    enrolled += 1

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
        qs = Enrollment.objects.select_related(
            'student', 'student__assigned_mentor', 'student__assigned_teacher', 'course'
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


# Mentor At-Risk Report (student-level assignment)
class MentorAtRiskView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Find students assigned to this mentor
        assigned_students = User.objects.filter(assigned_mentor=request.user, platform='classes', role='student')

        at_risk_data = []
        for student in assigned_students:
            records = AttendanceRecord.objects.filter(student=student)
            total = records.count()
            if total > 0:
                attended = records.filter(status__in=['Present', 'Late']).count()
                percentage = round((attended / total * 100))

                if percentage < 75:
                    at_risk_data.append({
                        "id": student.id,
                        "first_name": student.first_name,
                        "last_name": student.last_name,
                        "email": student.email,
                        "attendance_percentage": percentage
                    })

        at_risk_data = sorted(at_risk_data, key=lambda x: x['attendance_percentage'])
        return Response(at_risk_data)


# --- Admin Staff Management ---

class AdminStaffManagementView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return StaffCreateSerializer
        return BasicUserSerializer

    def get_queryset(self):
        return User.objects.filter(platform='classes', role__in=['teacher', 'mentor']).order_by('-date_joined')

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
        mentor_id = request.data.get('mentor_id')
        teacher_id = request.data.get('teacher_id')

        try:
            student = User.objects.get(pk=student_id, role='student')
        except User.DoesNotExist:
            return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

        if mentor_id:
            try:
                mentor = User.objects.get(pk=mentor_id, role='mentor')
                student.assigned_mentor = mentor
            except User.DoesNotExist:
                return Response({'detail': 'Mentor not found'}, status=status.HTTP_404_NOT_FOUND)
        elif mentor_id == '':
            student.assigned_mentor = None

        if teacher_id:
            try:
                teacher = User.objects.get(pk=teacher_id, role='teacher')
                student.assigned_teacher = teacher
            except User.DoesNotExist:
                return Response({'detail': 'Teacher not found'}, status=status.HTTP_404_NOT_FOUND)
        elif teacher_id == '':
            student.assigned_teacher = None

        student.save()
        return Response({'detail': 'Staff assignment updated.'})


class AdminStaffDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = StaffUpdateSerializer

    def get_queryset(self):
        return User.objects.filter(platform='classes', role__in=['teacher', 'mentor'])


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
            if user.assigned_mentor:
                data['user']['mentor'] = f"{user.assigned_mentor.first_name} {user.assigned_mentor.last_name}"
            if user.assigned_teacher:
                data['user']['teacher'] = f"{user.assigned_teacher.first_name} {user.assigned_teacher.last_name}"

        elif user.role == 'teacher':
            sessions = ClassSession.objects.filter(teacher=user, status='Completed')
            classes_taught = sessions.count()
            total_minutes = sessions.aggregate(total=Sum('duration_minutes'))['total'] or 0
            
            # Avg attendance across all their sessions
            all_attendance = AttendanceRecord.objects.filter(class_session__teacher=user)
            total_records = all_attendance.count()
            present_records = all_attendance.filter(status='Present').count()
            avg_attendance_rate = round((present_records / total_records * 100) if total_records > 0 else 0, 1)

            data['analytics'] = {
                'classes_taught': classes_taught,
                'total_teaching_hours': round(total_minutes / 60, 1),
                'avg_student_attendance_rate': avg_attendance_rate,
            }

        elif user.role == 'mentor':
            assigned_students = User.objects.filter(assigned_mentor=user, platform='classes', role='student')
            total_assigned = assigned_students.count()
            
            # Calculate at-risk students (attendance < 75%)
            at_risk_count = 0
            for student in assigned_students:
                att = AttendanceRecord.objects.filter(student=student)
                t = att.count()
                p = att.filter(status='Present').count()
                rate = (p / t * 100) if t > 0 else 100
                if rate < 75:
                    at_risk_count += 1

            data['analytics'] = {
                'assigned_students': total_assigned,
                'at_risk_students': at_risk_count
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
        if request.user.role not in ['admin', 'mentor']:
            return Response({'error': 'Only admins and mentors can schedule demos.'}, status=403)
        student_id = request.data.get('student_id')
        teacher_id = request.data.get('teacher_id')
        course_id = request.data.get('course_id')
        scheduled_time = request.data.get('scheduled_time')

        try:
            student = User.objects.get(pk=student_id, role='student')
            teacher = User.objects.get(pk=teacher_id, role='teacher')
            course = Course.objects.get(pk=course_id)
        except (User.DoesNotExist, Course.DoesNotExist):
            return Response({'error': 'Invalid student, teacher, or course.'}, status=404)

        # Business rule: 1 teacher = 1 student (exclusive)
        # Check if this teacher already has an active enrollment with a DIFFERENT student
        existing = Enrollment.objects.filter(teacher=teacher).exclude(student=student).first()
        if existing:
            return Response({
                'error': f'{teacher.first_name} {teacher.last_name} is already assigned to another student ({existing.student.first_name} {existing.student.last_name}). Each teacher can only have 1 student.'
            }, status=400)

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
            
            # Business rule: 1 teacher = 1 student (exclusive)
            existing = Enrollment.objects.filter(teacher=demo.teacher).exclude(student=request.user).first()
            if existing:
                return Response({
                    'error': f'This teacher is already assigned to another student. Each teacher can only have 1 student.'
                }, status=400)

            # Create enrollment
            enrollment, created = Enrollment.objects.get_or_create(
                student=request.user,
                course=demo.course,
                defaults={'teacher': demo.teacher}
            )
            
            if not created and not enrollment.teacher:
                enrollment.teacher = demo.teacher
                enrollment.save()
                
            return Response({'message': 'Demo accepted and enrolled successfully.'})
        except ClassSession.DoesNotExist:
            return Response({'error': 'Demo not found'}, status=404)


class BookSessionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        course_id = request.data.get('course_id')
        scheduled_time = request.data.get('scheduled_time')

        try:
            enrollment = Enrollment.objects.get(student=request.user, course_id=course_id)
            teacher = enrollment.teacher
            if not teacher:
                return Response({'error': 'No teacher assigned for this course.'}, status=400)
            
            session = ClassSession.objects.create(
                student=request.user,
                teacher=teacher,
                course=enrollment.course,
                title=f"1-to-1 Class: {enrollment.course.name}",
                scheduled_time=scheduled_time,
                duration_minutes=60,
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

