# api/serializers.py
from rest_framework import serializers
from .models import * # Import all new models
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['is_staff'] = user.is_staff
        token['role'] = user.role
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        if not user.is_active:
            raise AuthenticationFailed(
                'Account is inactive. Please verify your email to activate it.',
                'no_active_account'
            )
        return data

class UserSerializer(serializers.ModelSerializer):
    branch = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role', 'student_id', 'branch')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        branch_id = validated_data.pop('branch', None)
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        
        if branch_id:
            try:
                branch = Branch.objects.get(id=branch_id)
                user.branch = branch
            except Branch.DoesNotExist:
                pass 
        
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

# --- NEW MOCK TEST SERIALIZERS ---

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['id', 'text']

class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True)
    class Meta:
        model = Question
        fields = ['id', 'text', 'marks', 'choices']

class QuizSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)
    class Meta:
        model = Quiz
        fields = ['id', 'title', 'branch', 'duration_minutes', 'is_active', 'questions']
        read_only_fields = ['branch'] # Branch will be set from the admin user

# --- Serializers for creating quizzes ---

class ChoiceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['text', 'is_correct']

class QuestionCreateSerializer(serializers.ModelSerializer):
    choices = ChoiceCreateSerializer(many=True)

    class Meta:
        model = Question
        fields = ['text', 'marks', 'choices']

    def create(self, validated_data):
        choices_data = validated_data.pop('choices')
        question = Question.objects.create(**validated_data)
        for choice_data in choices_data:
            Choice.objects.create(question=question, **choice_data)
        return question

# --- Serializers for analytics ---

class StudentAnswerSerializer(serializers.ModelSerializer):
    question = serializers.StringRelatedField()
    selected_choice = serializers.StringRelatedField()
    class Meta:
        model = StudentAnswer
        fields = ['question', 'selected_choice', 'is_correct']

class StudentResultSerializer(serializers.ModelSerializer):
    quiz = serializers.StringRelatedField()
    answers = StudentAnswerSerializer(many=True, read_only=True)
    student = serializers.StringRelatedField()
    
    class Meta:
        model = StudentResult
        fields = ['id', 'student', 'quiz', 'score', 'total_marks', 'timestamp', 'answers']