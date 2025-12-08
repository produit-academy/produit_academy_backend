from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session, 
    Question, Choice, MockTest, MockTestQuestion
)

# --- AUTH & CORE SERIALIZERS (Unchanged from original) ---

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
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        if not self.user.is_active:
            raise AuthenticationFailed('Account is inactive.')
        return data

class UserSerializer(serializers.ModelSerializer):
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

class StudyMaterialSerializer(serializers.ModelSerializer):
    class Meta: model = StudyMaterial; fields = '__all__'

class CourseRequestSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    branch = BranchSerializer(read_only=True)
    class Meta: model = CourseRequest; fields = '__all__'

# --- QUESTION BANK SERIALIZERS (ADMIN) ---

# deleted CategorySerializer

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['id', 'text', 'is_correct']

class QuestionBankSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True)
    branch_name = serializers.CharField(source='branch.name', read_only=True)
    
    class Meta:
        model = Question
        fields = ['id', 'text', 'category', 'branch', 'branch_name', 'marks', 'choices']
    
    def create(self, validated_data):
        choices_data = validated_data.pop('choices')
        question = Question.objects.create(**validated_data)
        for choice_data in choices_data:
            Choice.objects.create(question=question, **choice_data)
        return question

    def update(self, instance, validated_data):
        instance.text = validated_data.get('text', instance.text)
        instance.category = validated_data.get('category', instance.category)
        instance.branch = validated_data.get('branch', instance.branch)
        instance.marks = validated_data.get('marks', instance.marks)
        instance.save()

        if 'choices' in validated_data:
            choices_data = validated_data.pop('choices')
            instance.choices.all().delete()
            for choice_data in choices_data:
                Choice.objects.create(instance, **choice_data)
        return instance

# --- MOCK TEST SERIALIZERS (STUDENT) ---

class MockTestGeneratorSerializer(serializers.Serializer):
    branch_id = serializers.IntegerField(required=False, allow_null=True)
    categories = serializers.ListField(child=serializers.CharField(), required=False, allow_null=True)
    number_of_questions = serializers.IntegerField(min_value=1, max_value=100, default=10)
    time_limit_minutes = serializers.IntegerField(min_value=5, max_value=180, default=30)
    allow_repeats = serializers.BooleanField(default=True)

# 1. Taking the Test (Hides Correct Answers)
class StudentChoiceSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['id', 'text'] # No is_correct

class MockTestQuestionSerializer(serializers.ModelSerializer):
    question_text = serializers.CharField(source='question.text', read_only=True)
    question_id = serializers.IntegerField(source='question.id', read_only=True)
    marks = serializers.IntegerField(source='question.marks', read_only=True)
    choices = StudentChoiceSerializer(source='question.choices', many=True, read_only=True)
    
    class Meta:
        model = MockTestQuestion
        fields = ['id', 'question_id', 'question_text', 'marks', 'choices', 'order']

class MockTestSessionSerializer(serializers.ModelSerializer):
    questions = MockTestQuestionSerializer(source='test_questions', many=True, read_only=True)
    
    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'total_questions', 'time_limit_minutes', 'questions']

# 2. Test Submission
class AnswerSubmissionSerializer(serializers.Serializer):
    question_id = serializers.IntegerField()
    choice_id = serializers.IntegerField()

class MockTestSubmitSerializer(serializers.Serializer):
    answers = serializers.ListField(child=AnswerSubmissionSerializer())

# 3. Analytics & Review (Shows Correct Answers)
class QuestionReviewSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True) # Includes is_correct
    class Meta: model = Question; fields = ['id', 'text', 'choices', 'marks', 'category']

class MockTestQuestionReviewSerializer(serializers.ModelSerializer):
    question = QuestionReviewSerializer(read_only=True)
    selected_choice = ChoiceSerializer(read_only=True)
    
    class Meta:
        model = MockTestQuestion
        fields = ['id', 'question', 'selected_choice', 'is_correct']

class MockTestResultSerializer(serializers.ModelSerializer):
    questions = MockTestQuestionReviewSerializer(source='test_questions', many=True, read_only=True)
    category_analysis = serializers.SerializerMethodField()

    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'completed_at', 'score', 'total_questions', 'time_limit_minutes', 'questions', 'category_analysis']

    def get_category_analysis(self, obj):
        # Calculate performance per category
        analysis = {}
        for tq in obj.test_questions.all():
            cat_name = tq.question.category or "Uncategorized"
            if cat_name not in analysis:
                analysis[cat_name] = {'total': 0, 'correct': 0}
            analysis[cat_name]['total'] += 1
            if tq.is_correct:
                analysis[cat_name]['correct'] += 1
        return analysis

class MockTestHistorySerializer(serializers.ModelSerializer):
    total_marks = serializers.SerializerMethodField()

    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'completed_at', 'score', 'total_questions', 'is_completed', 'total_marks']

    def get_total_marks(self, obj):
        # Calculate total possible marks for this test
        total = 0
        for tq in obj.test_questions.all():
            total += tq.question.marks
        return total