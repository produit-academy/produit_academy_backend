from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import User, Branch, CourseRequest, Session

# --- AUTH & CORE SERIALIZERS ---

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        if user.is_superuser or user.is_staff:
            token['role'] = 'admin'
        else:
            token['role'] = user.role
        token['profile_complete'] = bool(user.college and user.phone_number)
        token['platform'] = user.platform
        return token

    def validate(self, attrs):
        # Manually check for inactive user (unverified) *before* standard auth fails
        email = attrs.get('email') or attrs.get('username')
        password = attrs.get('password')

        if email and password:
            user = User.objects.filter(email=email).first()
            if user:
                # Check password manually to distinguish between "Wrong Password" and "Inactive"
                if user.check_password(password):
                    if not user.is_active:
                         raise AuthenticationFailed('Account is inactive.')

        data = super().validate(attrs)
        
        # Double check (though usually caught above)
        if not self.user.is_active:
            raise AuthenticationFailed('Account is inactive.')
            
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