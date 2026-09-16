from rest_framework import serializers
from api.models import (
    User, Branch, Department, StaffProfile, StaffTask, TaskComment,
    StaffWallet, WalletTransaction, TaskSubmissionHistory, TaskPaymentAuditLog
)


class DepartmentSerializer(serializers.ModelSerializer):
    staff_count = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = ['id', 'name', 'description', 'allowed_modules', 'is_active', 'staff_count', 'created_at']

    def get_staff_count(self, obj):
        return obj.staff_members.count()


class StaffProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)
    full_name = serializers.SerializerMethodField()
    role = serializers.CharField(source='user.role', read_only=True)
    phone_number = serializers.CharField(source='user.phone_number', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    department_modules = serializers.JSONField(source='department.allowed_modules', read_only=True)
    assigned_modules = serializers.JSONField(required=False, default=list)
    effective_modules = serializers.SerializerMethodField()

    class Meta:
        model = StaffProfile
        fields = [
            'id', 'email', 'full_name', 'role', 'phone_number',
            'department', 'department_name', 'department_modules',
            'assigned_modules', 'effective_modules',
            'designation', 'profile_picture', 'bio', 'joined_at'
        ]

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.email

    def get_effective_modules(self, obj):
        if obj.assigned_modules is not None:
            return obj.assigned_modules
        if obj.department and obj.department.allowed_modules:
            return obj.department.allowed_modules
        return []


class TaskCommentSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskComment
        fields = ['id', 'task', 'author_email', 'author_name', 'text', 'created_at']
        read_only_fields = ['task', 'author_email', 'author_name', 'created_at']

    def get_author_name(self, obj):
        return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.email


class TaskSubmissionHistorySerializer(serializers.ModelSerializer):
    submitted_by_name = serializers.SerializerMethodField()
    reviewed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskSubmissionHistory
        fields = [
            'id', 'task', 'submitted_by', 'submitted_by_name',
            'submission_report', 'submission_file', 'submission_image',
            'time_spent_hours', 'submitted_at', 'reviewer_feedback',
            'reviewed_by', 'reviewed_by_name', 'reviewed_at'
        ]
        read_only_fields = ['submitted_by', 'submitted_at', 'reviewed_by', 'reviewed_at']

    def get_submitted_by_name(self, obj):
        return f"{obj.submitted_by.first_name} {obj.submitted_by.last_name}".strip() or obj.submitted_by.email

    def get_reviewed_by_name(self, obj):
        if obj.reviewed_by:
            return f"{obj.reviewed_by.first_name} {obj.reviewed_by.last_name}".strip() or obj.reviewed_by.email
        return None


class TaskPaymentAuditLogSerializer(serializers.ModelSerializer):
    changed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskPaymentAuditLog
        fields = [
            'id', 'task', 'changed_by', 'changed_by_name',
            'old_amount', 'new_amount', 'old_status', 'new_status',
            'reason', 'created_at'
        ]
        read_only_fields = ['changed_by', 'created_at']

    def get_changed_by_name(self, obj):
        if obj.changed_by:
            return f"{obj.changed_by.first_name} {obj.changed_by.last_name}".strip() or obj.changed_by.email
        return 'System'


class StaffTaskSerializer(serializers.ModelSerializer):
    comments = TaskCommentSerializer(many=True, read_only=True)
    submission_history = TaskSubmissionHistorySerializer(many=True, read_only=True)
    assigned_to_email = serializers.EmailField(source='assigned_to.email', read_only=True)
    assigned_to_name = serializers.SerializerMethodField()
    assigned_by_email = serializers.EmailField(source='assigned_by.email', read_only=True)
    assigned_by_name = serializers.SerializerMethodField()
    reviewed_by_name = serializers.SerializerMethodField()
    payment_assigned_by_name = serializers.SerializerMethodField()
    payment_approved_by_name = serializers.SerializerMethodField()
    is_paid = serializers.SerializerMethodField()

    class Meta:
        model = StaffTask
        fields = [
            'id', 'title', 'description', 'status', 'remarks',
            'due_date', 'created_at', 'completed_at',
            'assigned_to', 'assigned_to_email', 'assigned_to_name',
            'assigned_by', 'assigned_by_email', 'assigned_by_name',
            
            # Submission proof fields
            'submission_report', 'submission_file', 'submission_image',
            'time_spent_hours', 'submitted_at', 'reviewer_feedback',
            'reviewed_by', 'reviewed_by_name', 'reviewed_at', 'revision_count',
            
            # Postpaid payment fields
            'payment_amount', 'payment_status',
            'payment_assigned_by', 'payment_assigned_by_name', 'payment_assigned_at',
            'payment_approved_by', 'payment_approved_by_name', 'payment_approved_at',
            'payment_notes', 'paid_at',
            
            'comments', 'submission_history', 'is_paid'
        ]
        read_only_fields = [
            'created_at', 'assigned_by', 'assigned_by_email', 'assigned_by_name',
            'assigned_to_email', 'assigned_to_name', 'reviewed_by', 'reviewed_by_name',
            'reviewed_at', 'payment_assigned_by', 'payment_assigned_at',
            'payment_approved_by', 'payment_approved_at', 'paid_at', 'is_paid'
        ]

    def get_assigned_to_name(self, obj):
        return f"{obj.assigned_to.first_name} {obj.assigned_to.last_name}".strip() or obj.assigned_to.email

    def get_assigned_by_name(self, obj):
        if obj.assigned_by:
            return f"{obj.assigned_by.first_name} {obj.assigned_by.last_name}".strip() or obj.assigned_by.email
        return None

    def get_reviewed_by_name(self, obj):
        if obj.reviewed_by:
            return f"{obj.reviewed_by.first_name} {obj.reviewed_by.last_name}".strip() or obj.reviewed_by.email
        return None

    def get_payment_assigned_by_name(self, obj):
        if obj.payment_assigned_by:
            return f"{obj.payment_assigned_by.first_name} {obj.payment_assigned_by.last_name}".strip() or obj.payment_assigned_by.email
        return None

    def get_payment_approved_by_name(self, obj):
        if obj.payment_approved_by:
            return f"{obj.payment_approved_by.first_name} {obj.payment_approved_by.last_name}".strip() or obj.payment_approved_by.email
        return None

    def get_is_paid(self, obj):
        return obj.payment_status == 'paid' or obj.payment.filter(type='credit').exists()


class SuperAdminUserSerializer(serializers.ModelSerializer):
    branch_name = serializers.CharField(source='branch.name', read_only=True)
    department_name = serializers.SerializerMethodField()
    department_id = serializers.SerializerMethodField()
    designation = serializers.SerializerMethodField()
    modules = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'role', 'platform',
            'phone_number', 'branch', 'branch_name',
            'department_id', 'department_name', 'designation', 'modules',
            'is_active', 'is_verified', 'date_joined',
        ]

    def get_department_name(self, obj):
        try:
            return obj.staff_profile.department.name if obj.staff_profile.department else None
        except Exception:
            return None

    def get_department_id(self, obj):
        try:
            return obj.staff_profile.department_id
        except Exception:
            return None

    def get_designation(self, obj):
        try:
            return obj.staff_profile.designation
        except Exception:
            return None

    def get_modules(self, obj):
        try:
            profile = obj.staff_profile
            if profile.assigned_modules is not None:
                return profile.assigned_modules
            if profile.department and profile.department.allowed_modules:
                return profile.department.allowed_modules
            return []
        except Exception:
            return []


# --- WALLET SERIALIZERS ---

class WalletTransactionSerializer(serializers.ModelSerializer):
    task_title = serializers.CharField(source='task.title', read_only=True, default=None)

    class Meta:
        model = WalletTransaction
        fields = ['id', 'type', 'amount', 'note', 'task_title', 'created_at']
        read_only_fields = ['created_at']


class StaffWalletSerializer(serializers.ModelSerializer):
    transactions = WalletTransactionSerializer(many=True, read_only=True)
    balance = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    staff_email = serializers.EmailField(source='staff.email', read_only=True)
    staff_name = serializers.SerializerMethodField()
    staff_role = serializers.CharField(source='staff.role', read_only=True)
    role_display = serializers.SerializerMethodField()
    hourly_rate = serializers.SerializerMethodField()
    phone_number = serializers.CharField(source='staff.phone_number', read_only=True, default='')

    class Meta:
        model = StaffWallet
        fields = ['id', 'staff', 'staff_email', 'staff_name', 'staff_role', 'role_display',
                  'hourly_rate', 'phone_number',
                  'total_earned', 'total_paid', 'balance', 'transactions', 'updated_at']

    def get_staff_name(self, obj):
        return f"{obj.staff.first_name} {obj.staff.last_name}".strip() or obj.staff.email

    def get_role_display(self, obj):
        if obj.staff.role == 'teacher':
            try:
                if obj.staff.classes_teacher_profile.is_approved:
                    return 'Teacher (Approved)'
                return 'Teacher (Pending)'
            except Exception:
                return 'Teacher'
        return obj.staff.role.capitalize() if obj.staff.role else 'Staff'

    def get_hourly_rate(self, obj):
        if obj.staff.role == 'teacher':
            try:
                return str(obj.staff.classes_teacher_profile.hourly_rate)
            except Exception:
                return '0.00'
        return None


class ManagerStaffSerializer(serializers.ModelSerializer):
    """Serializer for manager to see all staff/teachers/mentors."""
    full_name = serializers.SerializerMethodField()
    department_name = serializers.SerializerMethodField()
    designation = serializers.SerializerMethodField()
    task_count = serializers.SerializerMethodField()
    wallet_balance = serializers.SerializerMethodField()
    modules = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'full_name', 'role', 'phone_number',
            'department_name', 'designation', 'modules', 'is_active',
            'task_count', 'wallet_balance', 'date_joined',
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email

    def get_department_name(self, obj):
        try:
            return obj.staff_profile.department.name if obj.staff_profile.department else None
        except Exception:
            return None

    def get_designation(self, obj):
        try:
            return obj.staff_profile.designation
        except Exception:
            return obj.get_role_display()

    def get_task_count(self, obj):
        return obj.assigned_tasks.count()

    def get_wallet_balance(self, obj):
        try:
            return str(obj.wallet.balance)
        except Exception:
            return '0.00'

    def get_modules(self, obj):
        try:
            profile = obj.staff_profile
            if profile.assigned_modules is not None:
                return profile.assigned_modules
            if profile.department and profile.department.allowed_modules:
                return profile.department.allowed_modules
            return []
        except Exception:
            return []
