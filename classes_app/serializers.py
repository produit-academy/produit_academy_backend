from rest_framework import serializers
from api.models import User
from .models import Course, Enrollment, ClassSession, AttendanceRecord


class CourseTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


class CourseSerializer(serializers.ModelSerializer):
    mentor_name = serializers.CharField(source='mentor.username', read_only=True, default=None)
    teacher_list = CourseTeacherSerializer(source='teachers', many=True, read_only=True)
    student_count = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = [
            'id', 'name', 'description', 'mentor', 'mentor_name',
            'teachers', 'teacher_list', 'student_count', 'is_active', 'created_at'
        ]
        extra_kwargs = {
            'teachers': {'write_only': True, 'required': False},
            'mentor': {'required': False},
        }

    def get_student_count(self, obj):
        return obj.enrollments.count()


class EnrollmentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    student_email = serializers.CharField(source='student.email', read_only=True)
    course_name = serializers.CharField(source='course.name', read_only=True)

    class Meta:
        model = Enrollment
        fields = ['id', 'student', 'student_name', 'student_email', 'course', 'course_name', 'enrolled_at']


class ClassSessionSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name', read_only=True)
    teacher_name = serializers.CharField(source='teacher.username', read_only=True)
    attendance_submitted = serializers.SerializerMethodField()

    class Meta:
        model = ClassSession
        fields = [
            'id', 'course', 'course_name', 'teacher', 'teacher_name',
            'title', 'meeting_link', 'scheduled_time', 'duration_minutes',
            'status', 'attendance_submitted', 'created_at'
        ]
        read_only_fields = ['teacher', 'created_at']

    def get_attendance_submitted(self, obj):
        return obj.attendance.exists()


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
        fields = ['id', 'username', 'email', 'phone_number', 'existing_status']

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


class AtRiskStudentSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.CharField()
    phone_number = serializers.CharField(allow_null=True)
    attendance_percentage = serializers.FloatField()
    total_classes = serializers.IntegerField()
    attended = serializers.IntegerField()
    course_name = serializers.CharField()
    course_id = serializers.IntegerField()


class TeacherComplianceSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.CharField()
    total_sessions = serializers.IntegerField()
    attendance_marked = serializers.IntegerField()
    attendance_pending = serializers.IntegerField()
    course_name = serializers.CharField()


class MentorDashboardSerializer(serializers.Serializer):
    courses = CourseSerializer(many=True)
    at_risk_students = AtRiskStudentSerializer(many=True)
    teacher_compliance = TeacherComplianceSerializer(many=True)
    total_classes_this_week = serializers.IntegerField()
    total_students = serializers.IntegerField()


class AdminStatsSerializer(serializers.Serializer):
    total_students = serializers.IntegerField()
    total_teachers = serializers.IntegerField()
    total_mentors = serializers.IntegerField()
    total_courses = serializers.IntegerField()
    total_classes_this_month = serializers.IntegerField()
    active_students_today = serializers.IntegerField()
    overall_attendance_rate = serializers.FloatField()


class BulkEnrollSerializer(serializers.Serializer):
    course_id = serializers.IntegerField()
    student_emails = serializers.ListField(child=serializers.EmailField())
