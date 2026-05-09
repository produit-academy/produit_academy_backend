from rest_framework import serializers
from api.models import User, Branch, Department, StaffProfile, StaffTask, TaskComment, StaffWallet, WalletTransaction


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

    class Meta:
        model = StaffProfile
        fields = [
            'id', 'email', 'full_name', 'role', 'phone_number',
            'department', 'department_name', 'department_modules',
            'designation', 'profile_picture', 'bio', 'joined_at'
        ]

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.email


class TaskCommentSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskComment
        fields = ['id', 'task', 'author_email', 'author_name', 'text', 'created_at']
        read_only_fields = ['task', 'author_email', 'author_name', 'created_at']

    def get_author_name(self, obj):
        return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.email


class StaffTaskSerializer(serializers.ModelSerializer):
    comments = TaskCommentSerializer(many=True, read_only=True)
    assigned_to_email = serializers.EmailField(source='assigned_to.email', read_only=True)
    assigned_to_name = serializers.SerializerMethodField()
    assigned_by_email = serializers.EmailField(source='assigned_by.email', read_only=True)
    is_paid = serializers.SerializerMethodField()

    class Meta:
        model = StaffTask
        fields = [
            'id', 'title', 'description', 'status', 'remarks',
            'due_date', 'created_at', 'completed_at',
            'assigned_to', 'assigned_to_email', 'assigned_to_name',
            'assigned_by', 'assigned_by_email',
            'payment_amount', 'comments', 'is_paid'
        ]
        read_only_fields = ['created_at', 'assigned_by', 'assigned_by_email', 'assigned_to_email', 'assigned_to_name', 'is_paid']

    def get_assigned_to_name(self, obj):
        return f"{obj.assigned_to.first_name} {obj.assigned_to.last_name}".strip() or obj.assigned_to.email

    def get_is_paid(self, obj):
        return obj.payment.filter(type='credit').exists()


class SuperAdminUserSerializer(serializers.ModelSerializer):
    branch_name = serializers.CharField(source='branch.name', read_only=True)
    department_name = serializers.SerializerMethodField()
    designation = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'role', 'platform',
            'phone_number', 'branch', 'branch_name',
            'department_name', 'designation',
            'is_active', 'is_verified', 'date_joined',
        ]

    def get_department_name(self, obj):
        try:
            return obj.staff_profile.department.name if obj.staff_profile.department else None
        except Exception:
            return None

    def get_designation(self, obj):
        try:
            return obj.staff_profile.designation
        except Exception:
            return None


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

    class Meta:
        model = StaffWallet
        fields = ['id', 'staff', 'staff_email', 'staff_name', 'staff_role',
                  'total_earned', 'total_paid', 'balance', 'transactions', 'updated_at']

    def get_staff_name(self, obj):
        return f"{obj.staff.first_name} {obj.staff.last_name}".strip() or obj.staff.email


class ManagerStaffSerializer(serializers.ModelSerializer):
    """Serializer for manager to see all staff/teachers/mentors."""
    full_name = serializers.SerializerMethodField()
    department_name = serializers.SerializerMethodField()
    designation = serializers.SerializerMethodField()
    task_count = serializers.SerializerMethodField()
    wallet_balance = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'full_name', 'role', 'phone_number',
            'department_name', 'designation', 'is_active',
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
