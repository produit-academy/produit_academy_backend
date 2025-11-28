from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session, 
    Quiz, Question, Choice, QuizSubmission
)

# --- AUTHENTICATION SERIALIZERS ---

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        if user.is_superuser or user.is_staff:
            token['role'] = 'admin'
        else:
            token['role'] = user.role
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        if not user.is_active:
            raise AuthenticationFailed('Account is inactive. Please verify your email.')
        return data

class UserSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(queryset=Branch.objects.all(), required=False, allow_null=True)
    branch_name = serializers.CharField(source='branch.name', read_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role', 'student_id', 'branch', 'branch_name', 'college', 'phone_number')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        user.save()
        return user

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

# --- CORE MODELS SERIALIZERS ---

class BranchSerializer(serializers.ModelSerializer):
    class Meta: model = Branch; fields = '__all__'

class StudyMaterialSerializer(serializers.ModelSerializer):
    class Meta: model = StudyMaterial; fields = '__all__'

class CourseRequestSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    branch = BranchSerializer(read_only=True)
    class Meta: model = CourseRequest; fields = '__all__'

# --- QUIZ & EXAM SERIALIZERS ---

# 1. Student View (Taking the Quiz) - HIDES Correct Answers
class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['id', 'text'] # Excludes 'is_correct'

class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True)
    class Meta:
        model = Question
        fields = ['id', 'text', 'marks', 'choices']

class QuizSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True)
    class Meta:
        model = Quiz
        fields = ['id', 'title', 'duration_minutes', 'total_marks', 'questions']

# 2. Admin View (Creating Quiz) - Includes Write Logic
class ChoiceWriteSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['text', 'is_correct']

class QuestionWriteSerializer(serializers.ModelSerializer):
    choices = ChoiceWriteSerializer(many=True)
    class Meta: model = Question; fields = ['text', 'marks', 'choices']

class QuizCreateSerializer(serializers.ModelSerializer):
    questions = QuestionWriteSerializer(many=True)
    
    class Meta:
        model = Quiz
        fields = ['title', 'branch', 'duration_minutes', 'total_marks', 'questions']

    def create(self, validated_data):
        questions_data = validated_data.pop('questions')
        quiz = Quiz.objects.create(**validated_data)
        for q_data in questions_data:
            choices_data = q_data.pop('choices')
            question = Question.objects.create(quiz=quiz, **q_data)
            for c_data in choices_data:
                Choice.objects.create(question=question, **c_data)
        return quiz

    def update(self, instance, validated_data):
        # 1. Update Quiz Fields
        instance.title = validated_data.get('title', instance.title)
        instance.branch = validated_data.get('branch', instance.branch)
        instance.duration_minutes = validated_data.get('duration_minutes', instance.duration_minutes)
        instance.total_marks = validated_data.get('total_marks', instance.total_marks)
        instance.save()

        # 2. Handle Nested Questions
        # Strategy: Clear existing questions and re-create them (Simplest for MVP consistency)
        # Warning: This resets question IDs. 
        if 'questions' in validated_data:
            questions_data = validated_data.pop('questions')
            instance.questions.all().delete() # Delete old questions
            
            for q_data in questions_data:
                choices_data = q_data.pop('choices')
                question = Question.objects.create(quiz=instance, **q_data)
                for c_data in choices_data:
                    Choice.objects.create(question=question, **c_data)
        
        return instance

# 3. Analytics View (Viewing Results) - SHOWS Correct Answers
class ChoiceDetailSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['id', 'text', 'is_correct']

class QuestionResultSerializer(serializers.ModelSerializer):
    choices = ChoiceDetailSerializer(many=True)
    class Meta: model = Question; fields = ['id', 'text', 'marks', 'choices']

class QuizResultSerializer(serializers.ModelSerializer):
    questions = QuestionResultSerializer(many=True)
    class Meta: model = Quiz; fields = ['id', 'title', 'total_marks', 'questions']

class QuizSubmissionDetailSerializer(serializers.ModelSerializer):
    quiz = QuizResultSerializer()
    class Meta: model = QuizSubmission; fields = '__all__'