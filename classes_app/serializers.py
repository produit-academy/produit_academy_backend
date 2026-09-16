from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers
from api.models import User
from .models import (
    Course, Subject, Enrollment, ClassSession, AttendanceRecord,
    TeacherAvailability, TeacherProfile, TeacherDemoVideo,
    Booking, BookingSchedule, EmailLog,
    ClassReport, DailyClassVoiceNote, TeacherMonthlyReport,
)


class CourseSerializer(serializers.ModelSerializer):
    student_count = serializers.SerializerMethodField()
    subject_count = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = ['id', 'name', 'description', 'student_count', 'subject_count', 'is_active', 'created_at']

    def get_student_count(self, obj):
        if hasattr(obj, '_student_count'):
            return obj._student_count
        return obj.enrollments.count()

    def get_subject_count(self, obj):
        if hasattr(obj, '_subject_count'):
            return obj._subject_count
        return obj.subjects.filter(is_active=True).count()


class SubjectSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name', read_only=True)
    teacher_count = serializers.SerializerMethodField()

    class Meta:
        model = Subject
        fields = ['id', 'name', 'description', 'icon', 'course', 'course_name', 'teacher_count', 'is_active', 'created_at']

    def get_teacher_count(self, obj):
        if hasattr(obj, '_teacher_count'):
            return obj._teacher_count
        return obj.teachers.filter(is_approved=True).count()


class EnrollmentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    student_email = serializers.CharField(source='student.email', read_only=True)
    course_name = serializers.CharField(source='course.name', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    student_active = serializers.BooleanField(source='student.is_active', read_only=True)

    class Meta:
        model = Enrollment
        fields = [
            'id', 'student', 'student_name', 'student_email', 'student_active',
            'course', 'course_name', 'teacher_name', 'enrolled_at', 'is_completed'
        ]

    def get_teacher_name(self, obj):
        t = obj.teacher
        return f"{t.first_name} {t.last_name}" if t else None


class ClassSessionSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name', read_only=True)
    teacher_name = serializers.CharField(source='teacher.username', read_only=True)
    student_name = serializers.SerializerMethodField()
    attendance_submitted = serializers.SerializerMethodField()
    cancelled_by_name = serializers.SerializerMethodField()
    effective_status = serializers.SerializerMethodField()
    has_meet_link = serializers.SerializerMethodField()
    outcome_marked_by_name = serializers.SerializerMethodField()

    class Meta:
        model = ClassSession
        fields = [
            'id', 'course', 'course_name', 'teacher', 'teacher_name',
            'title', 'meeting_link', 'scheduled_time', 'duration_minutes',
            'status', 'effective_status', 'has_meet_link',
            'attendance_submitted', 'created_at',
            'is_demo', 'student', 'student_name', 'teacher_notes',
            'cancel_reason', 'cancelled_by', 'cancelled_by_name',
            'outcome_remarks', 'outcome_marked_by', 'outcome_marked_by_name', 'outcome_marked_at',
            'meet_link_added_by', 'meet_link_updated_at'
        ]
        read_only_fields = ['teacher', 'created_at', 'outcome_marked_at', 'meet_link_updated_at']

    def get_attendance_submitted(self, obj):
        return obj.attendance.exists()

    def get_student_name(self, obj):
        if obj.student:
            return f"{obj.student.first_name} {obj.student.last_name}".strip() or obj.student.username
        return None

    def get_cancelled_by_name(self, obj):
        if obj.cancelled_by:
            return f"{obj.cancelled_by.first_name} {obj.cancelled_by.last_name}".strip() or obj.cancelled_by.username
        return None

    def get_effective_status(self, obj):
        now = timezone.now()
        if obj.status in ['Completed', 'Not Conducted', 'Cancelled']:
            return obj.status
        
        end_time = obj.scheduled_time + timedelta(minutes=obj.duration_minutes)
        if obj.scheduled_time <= now <= end_time:
            return 'Live'
        elif now > end_time:
            return 'Needs Review'
        return obj.status

    def get_has_meet_link(self, obj):
        return bool(obj.meeting_link and obj.meeting_link.strip())

    def get_outcome_marked_by_name(self, obj):
        if obj.outcome_marked_by:
            return f"{obj.outcome_marked_by.first_name} {obj.outcome_marked_by.last_name}".strip() or obj.outcome_marked_by.username
        return None


class AttendanceRecordSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    student_email = serializers.CharField(source='student.email', read_only=True)

    class Meta:
        model = AttendanceRecord
        fields = ['id', 'class_session', 'student', 'student_name', 'student_email', 'status', 'marked_by', 'timestamp']
        read_only_fields = ['marked_by', 'timestamp']


class BulkAttendanceItemSerializer(serializers.Serializer):
    student_id = serializers.IntegerField()
    status = serializers.ChoiceField(choices=['Present', 'Absent', 'Late'])


class BulkAttendanceSerializer(serializers.Serializer):
    records = BulkAttendanceItemSerializer(many=True)


class RosterStudentSerializer(serializers.ModelSerializer):
    existing_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'phone_number', 'existing_status']

    def get_existing_status(self, obj):
        session_id = self.context.get('session_id')
        if session_id:
            record = AttendanceRecord.objects.filter(
                class_session_id=session_id, student=obj
            ).first()
            return record.status if record else None
        return None


# --- Dashboard-specific serializers ---

class StudentDashboardSerializer(serializers.Serializer):
    upcoming_classes = ClassSessionSerializer(many=True)
    total_classes = serializers.IntegerField()
    present_count = serializers.IntegerField()
    absent_count = serializers.IntegerField()
    late_count = serializers.IntegerField()
    attendance_percentage = serializers.FloatField()
    courses = CourseSerializer(many=True)


class TeacherDashboardSerializer(serializers.Serializer):
    upcoming_classes = ClassSessionSerializer(many=True)
    pending_attendance = ClassSessionSerializer(many=True)
    total_classes_held = serializers.IntegerField()
    total_students = serializers.IntegerField()
    courses = CourseSerializer(many=True)


class AdminStatsSerializer(serializers.Serializer):
    total_students = serializers.IntegerField()
    total_teachers = serializers.IntegerField()
    total_courses = serializers.IntegerField()
    total_classes_this_month = serializers.IntegerField()
    active_students_today = serializers.IntegerField()
    overall_attendance_rate = serializers.FloatField()
    total_bookings = serializers.IntegerField()


class BulkEnrollSerializer(serializers.Serializer):
    course_id = serializers.IntegerField()
    student_emails = serializers.ListField(child=serializers.EmailField())

# --- Admin Staff Management ---

class BasicUserSerializer(serializers.ModelSerializer):
    teacher_name = serializers.SerializerMethodField()
    subjects = serializers.SerializerMethodField()
    is_approved = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'role', 'teacher_name', 'subjects', 'is_approved']

    def get_teacher_name(self, obj):
        """For students, get teacher names from enrollments."""
        if obj.role == 'student':
            from .models import Enrollment
            enrollments = Enrollment.objects.filter(student=obj, teacher__isnull=False).select_related('teacher', 'course')
            if enrollments.exists():
                return ', '.join(
                    f"{e.teacher.first_name} {e.teacher.last_name} ({e.course.name})"
                    for e in enrollments
                )
        return None

    def get_subjects(self, obj):
        if obj.role == 'teacher' and hasattr(obj, 'classes_teacher_profile'):
            return list(obj.classes_teacher_profile.subjects.values_list('id', flat=True))
        return []

    def get_is_approved(self, obj):
        if obj.role == 'teacher':
            return getattr(getattr(obj, 'classes_teacher_profile', None), 'is_approved', False)
        return False

class StaffCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'role']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_role(self, value):
        if value != 'teacher':
            raise serializers.ValidationError("Role must be 'teacher'.")
        return value

    def create(self, validated_data):
        user = User(
            username=validated_data['email'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=validated_data['role'],
            platform='classes',
            is_active=True
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class StaffUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'role']

    def validate_role(self, value):
        if value != 'teacher':
            raise serializers.ValidationError("Role must be 'teacher'.")
        return value

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'address', 'current_class', 'school_name', 'is_active']


class TeacherAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = TeacherAvailability
        fields = ['id', 'teacher', 'date', 'start_time', 'end_time', 'created_at']
        read_only_fields = ['teacher', 'created_at']


# --- NEW SERIALIZERS ---

class TeacherDemoVideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeacherDemoVideo
        fields = ['id', 'title', 'video_url', 'video_type', 'thumbnail_url', 'description', 'order', 'created_at']
        read_only_fields = ['created_at']


class TeacherProfileCardSerializer(serializers.ModelSerializer):
    """Compact teacher card for listings."""
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    name = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()
    subject_name = serializers.SerializerMethodField()
    availability_status = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = [
            'id', 'user_id', 'name', 'bio', 'qualification', 'experience',
            'profile_picture_url', 'subject_name', 'hourly_rate',
            'availability_status', 'google_meet_link',
        ]

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

    def get_subject_name(self, obj):
        subject_name = self.context.get('subject_name')
        if subject_name:
            return subject_name
        subject_id = self.context.get('subject_id')
        if subject_id:
            for s in obj.taught_subjects.all():
                if s.id == subject_id:
                    return s.name
        return None

    def get_availability_status(self, obj):
        available_user_ids = self.context.get('available_user_ids')
        if available_user_ids is not None:
            return 'Available' if obj.user_id in available_user_ids else 'Unavailable'
        from datetime import date as dt_date
        today = dt_date.today()
        has_slots = TeacherAvailability.objects.filter(
            teacher=obj.user,
            date__gte=today
        ).exists()
        return 'Available' if has_slots else 'Unavailable'


class TeacherProfileDetailSerializer(serializers.ModelSerializer):
    """Full teacher profile for detail page."""
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    name = serializers.SerializerMethodField()
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    profile_picture_url = serializers.SerializerMethodField()
    demo_videos = serializers.SerializerMethodField()
    availability_slots = serializers.SerializerMethodField()
    taught_subject_names = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = [
            'id', 'user_id', 'name', 'first_name', 'last_name', 'email', 'bio', 'qualification', 'experience',
            'skills', 'certifications', 'languages', 'teaching_style',
            'profile_picture_url', 'profile_picture_base64', 'hourly_rate', 'google_meet_link',
            'demo_videos', 'availability_slots', 'taught_subject_names',
        ]

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

    def get_demo_videos(self, obj):
        videos = TeacherDemoVideo.objects.filter(teacher=obj.user)
        return TeacherDemoVideoSerializer(videos, many=True).data

    def get_availability_slots(self, obj):
        from datetime import date as dt_date
        today = dt_date.today()
        # Get all future availability slots
        slots = list(TeacherAvailability.objects.filter(teacher=obj.user, date__gte=today))
        
        # Get all future schedules that are part of active/confirmed/completed bookings
        active_schedules = BookingSchedule.objects.filter(
            booking__teacher=obj.user,
            date__gte=today,
            booking__booking_status__in=['confirmed', 'completed'],
            status='scheduled'
        )
        
        # Build a set of (date, start_time) tuples that are already booked
        booked_times = set((s.date, s.start_time) for s in active_schedules)
        
        # Return all slots with an explicit is_booked flag
        slot_data = []
        for s in slots:
            data = TeacherAvailabilitySerializer(s).data
            data['is_booked'] = (s.date, s.start_time) in booked_times
            slot_data.append(data)
        
        return slot_data

    def get_taught_subject_names(self, obj):
        return list(obj.taught_subjects.filter(is_active=True).values('id', 'name', 'course__name'))


class BookingScheduleSerializer(serializers.ModelSerializer):
    cancelled_by_name = serializers.SerializerMethodField()

    class Meta:
        model = BookingSchedule
        fields = ['id', 'date', 'start_time', 'end_time', 'status', 'cancel_reason', 'cancelled_by_name', 'cancelled_at']

    def get_cancelled_by_name(self, obj):
        if obj.cancelled_by:
            return f"{obj.cancelled_by.first_name} {obj.cancelled_by.last_name}".strip() or obj.cancelled_by.username
        return None


class BookingSerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    student_email = serializers.EmailField(source='student.email', read_only=True)
    student_phone = serializers.CharField(source='student.phone_number', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    teacher_email = serializers.EmailField(source='teacher.email', read_only=True)
    subject_name = serializers.CharField(source='subject.name', read_only=True)
    course_name = serializers.CharField(source='course.name', read_only=True)
    schedules = BookingScheduleSerializer(many=True, read_only=True)

    class Meta:
        model = Booking
        fields = [
            'id', 'student', 'student_name', 'student_email', 'student_phone',
            'teacher', 'teacher_name', 'teacher_email',
            'subject', 'subject_name', 'course', 'course_name',
            'start_date', 'end_date', 'preferred_time', 'num_classes',
            'teacher_fee_per_class', 'platform_fee', 'total_amount',
            'advance_amount', 'remaining_amount',
            'payment_status', 'booking_status', 'google_meet_link',
            'schedules', 'created_at',
        ]
        read_only_fields = [
            'student', 'teacher_fee_per_class', 'platform_fee',
            'total_amount', 'advance_amount', 'remaining_amount',
            'payment_status', 'booking_status', 'google_meet_link', 'created_at',
        ]

    def get_student_name(self, obj):
        return f"{obj.student.first_name} {obj.student.last_name}".strip() or obj.student.username

    def get_teacher_name(self, obj):
        return f"{obj.teacher.first_name} {obj.teacher.last_name}".strip() or obj.teacher.username


class BookingCreateSerializer(serializers.Serializer):
    teacher_id = serializers.IntegerField()
    subject_id = serializers.IntegerField()
    slot_ids = serializers.ListField(child=serializers.IntegerField(), min_length=1)


class EmailLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailLog
        fields = ['id', 'recipient_email', 'subject', 'email_type', 'status', 'error_message', 'created_at']


class ClassReportSerializer(serializers.ModelSerializer):
    teacher_name = serializers.SerializerMethodField()
    student_name = serializers.SerializerMethodField()
    session_title = serializers.SerializerMethodField()
    reviewed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = ClassReport
        fields = [
            'id', 'class_session', 'session_title', 'teacher', 'teacher_name',
            'student', 'student_name', 'report_type', 'status',
            'performance_rating', 'attendance_observation', 'homework_completion',
            'strengths', 'areas_for_improvement', 'recommendations', 'text_report',
            'pdf_report', 'voice_note', 'voice_note_duration',
            'reviewed_by', 'reviewed_by_name', 'reviewed_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['teacher', 'created_at', 'updated_at', 'reviewed_at']

    def get_teacher_name(self, obj):
        return f"{obj.teacher.first_name} {obj.teacher.last_name}".strip() or obj.teacher.username

    def get_student_name(self, obj):
        if obj.student:
            return f"{obj.student.first_name} {obj.student.last_name}".strip() or obj.student.username
        return "Entire Class"

    def get_session_title(self, obj):
        return obj.class_session.title if obj.class_session else None

    def get_reviewed_by_name(self, obj):
        if obj.reviewed_by:
            return f"{obj.reviewed_by.first_name} {obj.reviewed_by.last_name}".strip() or obj.reviewed_by.username
        return None


class DailyClassVoiceNoteSerializer(serializers.ModelSerializer):
    teacher_name = serializers.SerializerMethodField()
    session_title = serializers.SerializerMethodField()

    class Meta:
        model = DailyClassVoiceNote
        fields = [
            'id', 'class_session', 'session_title', 'teacher', 'teacher_name',
            'student', 'date', 'audio_file', 'text_summary', 'duration_seconds',
            'status', 'created_at'
        ]
        read_only_fields = ['teacher', 'date', 'created_at']

    def get_teacher_name(self, obj):
        return f"{obj.teacher.first_name} {obj.teacher.last_name}".strip() or obj.teacher.username

    def get_session_title(self, obj):
        return obj.class_session.title


class TeacherMonthlyReportSerializer(serializers.ModelSerializer):
    teacher_name = serializers.SerializerMethodField()
    reviewed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TeacherMonthlyReport
        fields = [
            'id', 'teacher', 'teacher_name', 'month', 'year', 'status',
            'classes_conducted_count', 'classes_not_conducted_count',
            'total_teaching_hours', 'attendance_summary',
            'student_progress_notes', 'tasks_assigned_completed',
            'important_observations', 'voice_notes_count',
            'overall_remarks', 'next_month_recommendations', 'pdf_report_file',
            'submitted_at', 'reviewed_by', 'reviewed_by_name', 'reviewed_at'
        ]
        read_only_fields = ['teacher', 'submitted_at', 'reviewed_at']

    def get_teacher_name(self, obj):
        return f"{obj.teacher.first_name} {obj.teacher.last_name}".strip() or obj.teacher.username

    def get_reviewed_by_name(self, obj):
        if obj.reviewed_by:
            return f"{obj.reviewed_by.first_name} {obj.reviewed_by.last_name}".strip() or obj.reviewed_by.username
        return None
