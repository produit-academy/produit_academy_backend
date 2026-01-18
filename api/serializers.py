from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session, 
    Question, Choice, MockTest, MockTestQuestion, Complaint,
    ContactInquiry
)

# --- AUTH & CORE SERIALIZERS (Unchanged) ---

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
        fields = ('id', 'username', 'email', 'password', 'role', 'student_id', 'branch', 'branch_name', 'college', 'phone_number', 'is_active', 'course_request_status', 'date_joined')
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

class StudyMaterialSerializer(serializers.ModelSerializer):
    class Meta: model = StudyMaterial; fields = '__all__'

class CourseRequestSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    branch = BranchSerializer(read_only=True)
    class Meta: model = CourseRequest; fields = '__all__'

# --- QUESTION BANK SERIALIZERS (ADMIN) ---

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['id', 'text', 'is_correct', 'image']

class QuestionBankSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, required=False)
    branch_name = serializers.CharField(source='branch.name', read_only=True)
    
    class Meta:
        model = Question
        fields = ['id', 'text', 'image', 'category', 'branch', 'branch_name', 'marks', 'question_type', 'nat_min', 'nat_max', 'choices']
    
    def validate(self, data):
        if not data.get('text') and not data.get('image'):
            raise serializers.ValidationError("Either text or image must be provided for the question.")
        
        q_type = data.get('question_type', 'MCQ')
        choices_data = data.get('choices', [])

        if q_type == 'NAT':
            if data.get('nat_min') is None or data.get('nat_max') is None:
                raise serializers.ValidationError("NAT questions must have a valid numerical range (min and max).")
        else:
            # Check validation for MCQ and MSQ
            if not choices_data:
                raise serializers.ValidationError("MCQ and MSQ questions must have choices.")
            
            correct_count = sum(1 for c in choices_data if c.get('is_correct'))
            if q_type == 'MCQ' and correct_count != 1:
                raise serializers.ValidationError("MCQ must have exactly one correct answer.")
            if q_type == 'MSQ' and correct_count < 1:
                raise serializers.ValidationError("MSQ must have at least one correct answer.")

        return data

    def create(self, validated_data):
        choices_data = validated_data.pop('choices', [])
        question = Question.objects.create(**validated_data)
        
        if question.question_type != 'NAT':
            for choice_data in choices_data:
                if not choice_data.get('text') and not choice_data.get('image'):
                    raise serializers.ValidationError("Either text or image must be provided for all choices.")
                Choice.objects.create(question=question, **choice_data)
        return question

    def update(self, instance, validated_data):
        instance.text = validated_data.get('text', instance.text)
        instance.image = validated_data.get('image', instance.image)
        instance.category = validated_data.get('category', instance.category)
        instance.branch = validated_data.get('branch', instance.branch)
        instance.marks = validated_data.get('marks', instance.marks)
        instance.question_type = validated_data.get('question_type', instance.question_type)
        instance.nat_min = validated_data.get('nat_min', instance.nat_min)
        instance.nat_max = validated_data.get('nat_max', instance.nat_max)
        instance.save()

        if instance.question_type != 'NAT' and 'choices' in validated_data:
            choices_data = validated_data.pop('choices')
            instance.choices.all().delete()
            for choice_data in choices_data:
                Choice.objects.create(question=instance, **choice_data)
        elif instance.question_type == 'NAT':
            instance.choices.all().delete()
            
        return instance

# --- MOCK TEST SERIALIZERS (STUDENT) ---

class MockTestGeneratorSerializer(serializers.Serializer):
    branch_id = serializers.IntegerField(required=False, allow_null=True)
    categories = serializers.ListField(child=serializers.CharField(), required=False, allow_null=True)
    number_of_questions = serializers.IntegerField(min_value=1, max_value=100, default=65)
    time_limit_minutes = serializers.IntegerField(min_value=5, max_value=180, default=180)
    allow_repeats = serializers.BooleanField(default=True)
    question_types = serializers.ListField(child=serializers.CharField(), required=False, allow_null=True)

class ContactInquirySerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInquiry
        fields = '__all__'

class ComplaintSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    class Meta:
        model = Complaint
        fields = ['id', 'student', 'student_name', 'subject', 'description', 'status', 'resolution_comment', 'created_at', 'resolved_at']
        read_only_fields = ['student', 'created_at', 'resolved_at']

class StudentChoiceSerializer(serializers.ModelSerializer):
    class Meta: model = Choice; fields = ['id', 'text', 'image']

class MockTestQuestionSerializer(serializers.ModelSerializer):
    question_text = serializers.CharField(source='question.text', read_only=True)
    question_image = serializers.CharField(source='question.image', read_only=True)
    question_id = serializers.IntegerField(source='question.id', read_only=True)
    question_type = serializers.CharField(source='question.question_type', read_only=True)
    marks = serializers.IntegerField(source='question.marks', read_only=True)
    choices = StudentChoiceSerializer(source='question.choices', many=True, read_only=True)
    
    class Meta:
        model = MockTestQuestion
        fields = ['id', 'question_id', 'question_text', 'question_image', 'question_type', 'marks', 'choices', 'order']

class MockTestSessionSerializer(serializers.ModelSerializer):
    questions = MockTestQuestionSerializer(source='test_questions', many=True, read_only=True)
    
    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'total_questions', 'time_limit_minutes', 'questions']

class AnswerSubmissionSerializer(serializers.Serializer):
    question_id = serializers.IntegerField()
    answer = serializers.JSONField()

class MockTestSubmitSerializer(serializers.Serializer):
    answers = serializers.ListField(child=AnswerSubmissionSerializer())

class QuestionReviewSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True)
    class Meta: model = Question; fields = ['id', 'text', 'image', 'choices', 'marks', 'category', 'question_type', 'nat_min', 'nat_max']

class MockTestQuestionReviewSerializer(serializers.ModelSerializer):
    question = QuestionReviewSerializer(read_only=True)
    selected_choice = ChoiceSerializer(read_only=True)
    selected_choices = ChoiceSerializer(many=True, read_only=True)
    awarded_marks = serializers.SerializerMethodField()
    
    class Meta:
        model = MockTestQuestion
        fields = ['id', 'question', 'selected_choice', 'selected_choices', 'nat_answer', 'is_correct', 'awarded_marks']

    def get_awarded_marks(self, obj):
        if obj.is_correct:
            return obj.question.marks
        
        # Negative marking for wrong MCQ attempts (only if attempted)
        if obj.question.question_type == 'MCQ' and obj.selected_choice is not None:
             return round(-(obj.question.marks / 3.0), 2)
        
        return 0.0

class MockTestResultSummarySerializer(serializers.ModelSerializer):
    category_analysis = serializers.SerializerMethodField()

    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'completed_at', 'score', 'total_questions', 'time_limit_minutes', 'category_analysis']

    def get_category_analysis(self, obj):
        analysis = {}
        for tq in obj.test_questions.all():
            try:
                cat_name = tq.question.category or "Uncategorized"
                if cat_name not in analysis:
                    analysis[cat_name] = {'total': 0, 'correct': 0}
                analysis[cat_name]['total'] += 1
                if tq.is_correct:
                    analysis[cat_name]['correct'] += 1
            except Exception:
                continue
        return analysis

class MockTestHistorySerializer(serializers.ModelSerializer):
    total_marks = serializers.SerializerMethodField()

    class Meta:
        model = MockTest
        fields = ['id', 'created_at', 'completed_at', 'score', 'total_questions', 'is_completed', 'total_marks']

    def get_total_marks(self, obj):
        total = 0
        for tq in obj.test_questions.all():
            try:
                total += tq.question.marks
            except Exception:
                continue
        return total