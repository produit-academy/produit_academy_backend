from django.shortcuts import get_object_or_404
from django.http import FileResponse, Http404
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework import generics, permissions, status, parsers, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination

from api.models import (
    User, Branch, StudyMaterial, CourseRequest,
    Question, Choice, MockTest, MockTestQuestion
)
from api.views import send_html_email
from .serializers import (
    StudyMaterialSerializer, CourseRequestSerializer,
    QuestionBankSerializer, MockTestGeneratorSerializer,
    MockTestSessionSerializer, MockTestSubmitSerializer, MockTestResultSummarySerializer,
    MockTestHistorySerializer, MockTestQuestionReviewSerializer,
)


# --- PAGINATION ---

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# --- COURSE & MATERIALS ---

class CourseRequestView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CourseRequestSerializer
    def get_queryset(self):
        return CourseRequest.objects.filter(student=self.request.user)
    def perform_create(self, serializer):
        serializer.save(student=self.request.user, status='Pending')

class CourseRequestUpdateView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = CourseRequest.objects.all()
    serializer_class = CourseRequestSerializer

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status == 'Approved':
            student = instance.student
            student.is_active = True
            student.save()
            
            # Send Approval Email
            try:
                send_html_email(
                    subject="Course Request Approved - Produit Academy",
                    recipient_email=student.email,
                    username=student.username,
                    otp=None, # Not needed for approval
                    type='approval'
                )
            except Exception as e:
                print(f"Failed to send approval email: {e}")

class StudyMaterialView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = StudyMaterialSerializer
    def get_queryset(self):
        user = self.request.user
        if not user.branch:
            return StudyMaterial.objects.none()
        is_approved = CourseRequest.objects.filter(student=user, branch=user.branch, status='Approved').exists()
        if is_approved:
            return StudyMaterial.objects.filter(branch=user.branch)
        else:
            return StudyMaterial.objects.filter(branch=user.branch, is_preview=True)

class StudyMaterialUploadView(generics.CreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]
    queryset = StudyMaterial.objects.all()
    serializer_class = StudyMaterialSerializer

class MaterialFileView(APIView):
    permission_classes = [permissions.AllowAny] 
    def get(self, request, pk):
        try:
            material = StudyMaterial.objects.get(pk=pk)
            response = FileResponse(material.file.open(), content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{material.file.name}"'
            return response
        except StudyMaterial.DoesNotExist:
            raise Http404


# --- ADMIN: QUESTION BANK & CATEGORY MANAGEMENT ---

class AdminQuestionBankView(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAdminUser]
    queryset = Question.objects.all().select_related('branch').prefetch_related('choices').order_by('-created_at')
    serializer_class = QuestionBankSerializer
    pagination_class = StandardResultsSetPagination


# --- STUDENT: CUSTOM MOCK TEST SYSTEM ---

class GenerateMockTestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MockTestGeneratorSerializer(data=request.data)
        if serializer.is_valid():
            # 1. Extract Preferences
            branch_id = serializer.validated_data.get('branch_id')
            categories = serializer.validated_data.get('categories')
            num_questions = serializer.validated_data.get('number_of_questions')
            time_limit = serializer.validated_data.get('time_limit_minutes')
            allow_repeats = serializer.validated_data.get('allow_repeats')

            # 2. Filter Questions
            questions_query = Question.objects.all()
            if branch_id:
                from django.db.models import Q
                questions_query = questions_query.filter(Q(branch_id=branch_id) | Q(category='General Aptitude'))

            if categories:
                questions_query = questions_query.filter(category__in=categories)

            question_types = serializer.validated_data.get('question_types')
            if question_types:
                questions_query = questions_query.filter(question_type__in=question_types)
            
            if not allow_repeats:
                attempted_q_ids = MockTestQuestion.objects.filter(
                    mock_test__student=request.user
                ).values_list('question_id', flat=True)
                questions_query = questions_query.exclude(id__in=attempted_q_ids)

            # 3. Weighted Selection Logic
            import random
            
            selected_ids = []
            
            # Check if we should apply the standard pattern (GA: 15%, Math: 15%, Core: 70%)
            # Apply if:
            # 1. No specific categories selected (Standard Test)
            # 2. All 3 categories are explicitly selected
            all_categories = {'General Aptitude', 'Engineering Mathematics', 'Subject Paper'}
            is_standard_selection = not categories or set(categories) == all_categories
            
            if is_standard_selection:
                # Determine Branch Specific Logic
                is_architecture = False
                if branch_id:
                    try:
                        branch_obj = Branch.objects.get(id=branch_id)
                        if "Architecture" in branch_obj.name:
                            is_architecture = True
                    except Branch.DoesNotExist:
                        pass
                
                if num_questions == 65:
                    if is_architecture:
                        # --- ARCHITECTURE GATE PATTERN (100 Marks, No Math) ---
                        # GA: 5x1 + 5x2 = 15 Marks (10 Qs)
                        # Core: 25x1 + 30x2 = 85 Marks (55 Qs)
                        # Total: 10 + 55 = 65 Qs | 15 + 85 = 100 Marks
                        
                        def get_exact_marks_ids(cat_name, target_1_mark, target_2_mark):
                            cat_query = questions_query.filter(category=cat_name)
                            ids_1 = list(cat_query.filter(marks=1).values_list('id', flat=True))
                            ids_2 = list(cat_query.filter(marks=2).values_list('id', flat=True))
                            selected = []
                            if len(ids_1) >= target_1_mark: selected += random.sample(ids_1, target_1_mark)
                            else: selected += ids_1
                            if len(ids_2) >= target_2_mark: selected += random.sample(ids_2, target_2_mark)
                            else: selected += ids_2
                            return selected

                        ids_ga = get_exact_marks_ids('General Aptitude', 5, 5)
                        ids_core = get_exact_marks_ids('Subject Paper', 25, 30)
                        
                        selected_ids = ids_ga + ids_core

                    else:
                        # --- STANDARD GATE PATTERN (100 Marks) ---
                        # GA: 5x1 + 5x2 = 15 Marks
                        # Math: 5x1 + 5x2 = 15 Marks
                        # Core: 20x1 + 25x2 = 70 Marks
                        
                        def get_exact_marks_ids(cat_name, target_1_mark, target_2_mark):
                            cat_query = questions_query.filter(category=cat_name)
                            ids_1 = list(cat_query.filter(marks=1).values_list('id', flat=True))
                            ids_2 = list(cat_query.filter(marks=2).values_list('id', flat=True))
                            selected = []
                            if len(ids_1) >= target_1_mark: selected += random.sample(ids_1, target_1_mark)
                            else: selected += ids_1
                            if len(ids_2) >= target_2_mark: selected += random.sample(ids_2, target_2_mark)
                            else: selected += ids_2
                            return selected

                        ids_ga = get_exact_marks_ids('General Aptitude', 5, 5)
                        ids_math = get_exact_marks_ids('Engineering Mathematics', 5, 5)
                        ids_core = get_exact_marks_ids('Subject Paper', 20, 25)
                        
                        selected_ids = ids_ga + ids_math + ids_core
                    
                    # Fill if short
                    if len(selected_ids) < num_questions:
                         current_set = set(selected_ids)
                         remaining_needed = num_questions - len(selected_ids)
                         remaining_pool = list(questions_query.exclude(id__in=current_set).values_list('id', flat=True))
                         if len(remaining_pool) >= remaining_needed:
                             selected_ids += random.sample(remaining_pool, remaining_needed)
                         else:
                             selected_ids += remaining_pool

                else:
                    # --- PERCENTAGE DISTRIBUTION (Custom N) ---
                    if is_architecture:
                        # Architecture: 15% GA, 85% Core
                        count_ga = int(num_questions * 0.15)
                        count_math = 0
                        count_core = num_questions - count_ga
                    else:
                        # Standard: 15% GA, 15% Math, 70% Core
                        count_ga = int(num_questions * 0.15)
                        count_math = int(num_questions * 0.15)
                        count_core = num_questions - count_ga - count_math
                    
                    def get_category_ids(cat_name, target_count):
                        if target_count <= 0: return []
                        cat_query = questions_query.filter(category=cat_name)
                        ids = list(cat_query.values_list('id', flat=True))
                        return random.sample(ids, min(len(ids), target_count))

                    ids_ga = get_category_ids('General Aptitude', count_ga)
                    ids_math = get_category_ids('Engineering Mathematics', count_math)
                    ids_core = get_category_ids('Subject Paper', count_core)
                    
                    selected_ids = ids_ga + ids_math + ids_core
                    
                    # Fill remaining
                    if len(selected_ids) < num_questions:
                        current_set = set(selected_ids)
                        remaining_needed = num_questions - len(selected_ids)
                        remaining_pool = list(questions_query.exclude(id__in=current_set).values_list('id', flat=True))
                        if len(remaining_pool) >= remaining_needed:
                            selected_ids += random.sample(remaining_pool, remaining_needed)
                        else:
                            selected_ids += remaining_pool
            else:
                # Randomly select from the filtered pool (User selected 1 or 2 specific categories)
                available_ids = list(questions_query.values_list('id', flat=True))
                if len(available_ids) >= num_questions:
                    selected_ids = random.sample(available_ids, num_questions)
                else:
                    selected_ids = available_ids

            if len(selected_ids) == 0:
                return Response(
                    {"error": "No questions available matching your criteria."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # 4. Create Mock Test
            mock_test = MockTest.objects.create(
                student=request.user,
                total_questions=len(selected_ids),
                time_limit_minutes=time_limit
            )

            mock_questions = []
            for q_id in selected_ids:
                mock_questions.append(MockTestQuestion(
                    mock_test=mock_test,
                    question_id=q_id
                ))
            
            MockTestQuestion.objects.bulk_create(mock_questions)

            return Response(MockTestSessionSerializer(mock_test).data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SubmitMockTestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        mock_test = get_object_or_404(MockTest, pk=pk, student=request.user)

        if mock_test.is_completed:
            return Response({"error": "Test already submitted."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = MockTestSubmitSerializer(data=request.data)
        if serializer.is_valid():
            total_score = 0.0
            answers_map = {item['question_id']: item['answer'] for item in serializer.validated_data['answers']}
            test_questions = MockTestQuestion.objects.filter(mock_test=mock_test).select_related('question')
            
            for tq in test_questions:
                question = tq.question
                q_type = question.question_type
                user_answer = answers_map.get(question.id)

                if user_answer is None:
                    continue # Not attempted

                if q_type == 'MCQ':
                    try:
                        selected_choice = Choice.objects.get(id=user_answer, question=question)
                        tq.selected_choice = selected_choice
                        
                        if selected_choice.is_correct:
                            tq.is_correct = True
                            total_score += question.marks
                        else:
                            tq.is_correct = False
                            total_score -= (question.marks / 3.0)
                            
                    except (Choice.DoesNotExist, ValueError):
                        pass

                elif q_type == 'MSQ':
                    if isinstance(user_answer, list):
                        selected_ids = set(user_answer)
                        correct_choice_ids = set(Choice.objects.filter(question=question, is_correct=True).values_list('id', flat=True))
                        
                        choices_to_add = Choice.objects.filter(id__in=selected_ids, question=question)
                        tq.selected_choices.set(choices_to_add)

                        if selected_ids == correct_choice_ids:
                            tq.is_correct = True
                            total_score += question.marks
                        else:
                            tq.is_correct = False

                elif q_type == 'NAT':
                    try:
                        val = float(user_answer)
                        tq.nat_answer = val
                        if question.nat_min is not None and question.nat_max is not None:
                            if question.nat_min <= val <= question.nat_max:
                                tq.is_correct = True
                                total_score += question.marks
                            else:
                                tq.is_correct = False
                    except (ValueError, TypeError):
                        pass
                
                tq.save()

            mock_test.score = round(total_score, 2)
            mock_test.is_completed = True
            mock_test.completed_at = timezone.now()
            mock_test.save()

            return Response({
                "message": "Test submitted successfully",
                "score": mock_test.score,
                "test_id": mock_test.id
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StudentMockTestHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MockTestHistorySerializer
    def get_queryset(self):
        return MockTest.objects.filter(student=self.request.user).order_by('-created_at')

class AdminStudentHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = MockTestHistorySerializer
    def get_queryset(self):
        student_id = self.kwargs['pk']
        return MockTest.objects.filter(student_id=student_id).order_by('-created_at')

class StudentMockTestAnalyticsView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MockTestResultSummarySerializer
    queryset = MockTest.objects.all()
    def get_object(self):
        obj = super().get_object()
        if obj.student != self.request.user:
            raise PermissionDenied("You do not have permission to view this test.")
        if not obj.is_completed:
            raise PermissionDenied("You must complete the test to view analytics.")
        return obj

class StudentMockTestQuestionsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MockTestQuestionReviewSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        test_id = self.kwargs['pk']
        
        # Verify ownership and completion
        try:
            mock_test = MockTest.objects.get(pk=test_id, student=self.request.user)
            if not mock_test.is_completed:
                raise PermissionDenied("Test not completed.")
        except MockTest.DoesNotExist:
            raise Http404

        return MockTestQuestion.objects.filter(mock_test_id=test_id).order_by('order').select_related('question', 'selected_choice').prefetch_related('question__choices', 'selected_choices')
