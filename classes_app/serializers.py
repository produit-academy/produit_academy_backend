from rest_framework import serializers
from api.models import User
from .models import Course, Enrollment, ClassSession, AttendanceRecord


class CourseSerializer(serializers.ModelSerializer):
    student_count = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = ['id', 'name', 'description', 'student_count', 'is_active', 'created_at']

    def get_student_count(self, obj):
        return obj.enrollments.count()


class EnrollmentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    student_email = serializers.CharField(source='student.email', read_only=True)
    course_name = serializers.CharField(source='course.name', read_only=True)
    mentor_name = serializers.SerializerMethodField()
    teacher_name = serializers.SerializerMethodField()

    student_active = serializers.BooleanField(source='student.is_active', read_only=True)

    class Meta:
        model = Enrollment
        fields = [
            'id', 'student', 'student_name', 'student_email', 'student_active',
            'course', 'course_name', 'mentor_name', 'teacher_name', 'enrolled_at', 'is_completed'
        ]

    def get_mentor_name(self, obj):
        m = obj.student.assigned_mentor
        return f"{m.first_name} {m.last_name}" if m else None

    def get_teacher_name(self, obj):
        t = obj.student.assigned_teacher
        return f"{t.first_name} {t.last_name}" if t else None


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
    total_mentors = serializers.IntegerField()
    total_courses = serializers.IntegerField()
    total_classes_this_month = serializers.IntegerField()
    active_students_today = serializers.IntegerField()
    overall_attendance_rate = serializers.FloatField()


class BulkEnrollSerializer(serializers.Serializer):
    course_id = serializers.IntegerField()
    student_emails = serializers.ListField(child=serializers.EmailField())

# --- Admin Staff Management ---

class BasicUserSerializer(serializers.ModelSerializer):
    mentor_name = serializers.SerializerMethodField()
    teacher_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'role', 'assigned_mentor', 'assigned_teacher', 'mentor_name', 'teacher_name']

    def get_mentor_name(self, obj):
        m = obj.assigned_mentor
        return f"{m.first_name} {m.last_name}" if m else None

    def get_teacher_name(self, obj):
        t = obj.assigned_teacher
        return f"{t.first_name} {t.last_name}" if t else None

class StaffCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'role']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_role(self, value):
        if value not in ['teacher', 'mentor']:
            raise serializers.ValidationError("Role must be either 'teacher' or 'mentor'.")
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
        if value not in ['teacher', 'mentor']:
            raise serializers.ValidationError("Role must be either 'teacher' or 'mentor'.")
        return value

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'address', 'current_class', 'school_name', 'is_active']

