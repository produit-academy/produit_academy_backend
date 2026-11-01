from django.core.cache import cache
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import User, Branch, CourseRequest, Session

from rest_framework_simplejwt.settings import api_settings
from django.contrib.auth.models import update_last_login

# --- AUTH & CORE SERIALIZERS ---

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Allow either email or username in the login payload
        self.fields['email'] = serializers.CharField(required=False, write_only=True)
        self.fields['username'] = serializers.CharField(required=False, write_only=True)
        self.fields['password'] = serializers.CharField(write_only=True)

    @classmethod
    def get_token(cls, user, session_id=None):
        token = super().get_token(user)
        token['username'] = user.username
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        if user.is_superuser:
            token['role'] = 'admin'
        else:
            token['role'] = user.role
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff
        token['profile_complete'] = bool(user.college and user.phone_number)
        token['platform'] = user.platform
        token['is_staff_user'] = (
            user.role in ['staff', 'manager', 'admin']
            or user.is_superuser
            or user.is_staff
            or hasattr(user, 'staff_profile')
        )
        if user.role == 'student' and not user.is_staff and not user.is_superuser:
            import uuid
            sid = session_id or uuid.uuid4().hex
            token['session_id'] = sid
        return token

    def validate(self, attrs):
        identifier = (attrs.get('email') or attrs.get('username') or '').strip()
        password = attrs.get('password') or ''

        if not identifier or not password:
            raise AuthenticationFailed('Email/username and password are required.')

        clean_id = identifier
        clean_email = clean_id.lower()
        # Fast indexed lookup first (email is unique B-tree index in Postgres)
        user = (
            User.objects.select_related('staff_profile').filter(email=clean_email).first()
            or User.objects.select_related('staff_profile').filter(email=clean_id).first()
            or User.objects.select_related('staff_profile').filter(username=clean_id).first()
            or User.objects.select_related('staff_profile').filter(email__iexact=clean_id).first()
            or User.objects.select_related('staff_profile').filter(username__iexact=clean_id).first()
        )

        if not user:
            raise AuthenticationFailed('No account found with this email or username.')

        # Account status and active check
        account_status = getattr(user, 'account_status', 'active')
        if not user.is_active or account_status in ['banned', 'hold']:
            reason = getattr(user, 'status_reason', '')
            msg = f"Account is {account_status}: {reason}" if reason else "Account is inactive or suspended. Please contact support."
            raise AuthenticationFailed(msg)

        if not user.has_usable_password():
            raise AuthenticationFailed('This account does not have a password set. Please use OTP login or complete your registration.')

        # Check login failure lockout
        fail_key = f"login_pwd_fail_{user.id}"
        fails = cache.get(fail_key, 0)
        if fails >= 5:
            raise AuthenticationFailed('Too many failed login attempts. Your account has been temporarily locked for 15 minutes for security.')

        if not user.check_password(password):
            new_fails = fails + 1
            cache.set(fail_key, new_fails, timeout=900)
            remaining = 5 - new_fails
            if remaining > 0:
                raise AuthenticationFailed(f'Incorrect password. {remaining} attempt(s) remaining before temporary lockout.')
            else:
                raise AuthenticationFailed('Too many failed login attempts. Your account has been temporarily locked for 15 minutes for security.')

        # Clear login failure counter on successful authentication
        cache.delete(fail_key)

        self.user = user
        import uuid
        session_id = uuid.uuid4().hex if (user.role == 'student' and not user.is_staff and not user.is_superuser) else None
        refresh = self.get_token(user, session_id=session_id)
        self.session_id = session_id

        is_staff_user = (
            user.role in ['staff', 'manager', 'admin']
            or user.is_superuser
            or user.is_staff
            or hasattr(user, 'staff_profile')
        )

        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': 'admin' if user.is_superuser else user.role,
            'is_staff_user': is_staff_user,
        }

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)

        return data

class UserSerializer(serializers.ModelSerializer):
    branch_name = serializers.CharField(source='branch.name', read_only=True)
    course_request_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role', 'platform', 'student_id', 'branch', 'branch_name', 'college', 'phone_number', 'is_active', 'course_request_status', 'date_joined')
        extra_kwargs = {'password': {'write_only': True}}
    
    def validate_password(self, value):
        if value:
            try:
                validate_password(value)
            except DjangoValidationError as ve:
                raise serializers.ValidationError(list(ve.messages))
        return value

    def get_course_request_status(self, obj):
        # Fetch the latest course request for this user
        req = CourseRequest.objects.filter(student=obj).last()
        return req.status if req else None

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        user.save()
        return user

class SignUpSerializer(UserSerializer):
    """Public self-registration: privilege fields can never be set by the client."""
    class Meta(UserSerializer.Meta):
        read_only_fields = ('role', 'platform', 'student_id', 'is_active')

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def validate_new_password(self, value):
        user = self.context['request'].user
        try:
            validate_password(value, user=user)
        except DjangoValidationError as ve:
            raise serializers.ValidationError(list(ve.messages))
        return value

    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        try:
            from .models import Session
            from django.core.cache import cache
            Session.objects.filter(user=instance).delete()
            cache.delete(f"user_active_session_{instance.id}")
        except Exception:
            pass
        return instance

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'college', 'phone_number')
        read_only_fields = ('email',)

class BranchSerializer(serializers.ModelSerializer):
    class Meta: model = Branch; fields = '__all__'