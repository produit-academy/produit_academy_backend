# api/serializers.py
from rest_framework import serializers
from .models import User, Branch, StudyMaterial, CourseRequest, Session
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed # Add this import

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['is_staff'] = user.is_staff
        token['role'] = user.role
        return token

    def validate(self, attrs):
        # This will authenticate the user, or raise an exception
        data = super().validate(attrs)

        # `self.user` is the user object that was successfully authenticated
        user = self.user

        # Add a custom check to see if the user's account is active
        if not user.is_active:
            raise AuthenticationFailed(
                'Account is inactive. Please verify your email to activate it.',
                'no_active_account'
            )

        # --- Session logic removed from here ---

        return data


class UserSerializer(serializers.ModelSerializer):
    branch = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role', 'student_id', 'branch')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data.pop('branch', None)
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        user.save()
        return user

class BranchSerializer(serializers.ModelSerializer):
    class Meta: model = Branch; fields = '__all__'
class StudyMaterialSerializer(serializers.ModelSerializer):
    class Meta: model = StudyMaterial; fields = '__all__'
class CourseRequestSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    branch = BranchSerializer(read_only=True)
    class Meta: model = CourseRequest; fields = '__all__'

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'college', 'phone_number')
        read_only_fields = ('email',)