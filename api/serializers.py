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
    def get_token(cls, user):
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
        token['is_staff_user'] = hasattr(user, 'staff_profile') or user.role in ['staff', 'manager', 'admin'] or user.is_superuser or user.is_staff
        return token

    def validate(self, attrs):
        identifier = (attrs.get('email') or attrs.get('username') or '').strip()
        password = attrs.get('password') or ''

        if not identifier or not password:
            raise AuthenticationFailed('Email/username and password are required.')

        # Case-insensitive lookup by email or username
        user = (
            User.objects.filter(email__iexact=identifier).first()
            or User.objects.filter(username__iexact=identifier).first()
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

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password. Please try again.')

        self.user = user
        refresh = self.get_token(user)

        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': 'admin' if user.is_superuser else user.role,
            'is_staff_user': hasattr(user, 'staff_profile') or user.role in ['staff', 'manager', 'admin'] or user.is_superuser or user.is_staff,
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
    
    def get_course_request_status(self, obj):
        # Fetch the latest course request for this user
        req = CourseRequest.objects.filter(student=obj).last()
        return req.status if req else None

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        user.save()
        return user

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    def validate_old_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value
    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'college', 'phone_number')
        read_only_fields = ('email',)

class BranchSerializer(serializers.ModelSerializer):
    class Meta: model = Branch; fields = '__all__'