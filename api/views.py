from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404
from django.utils.html import strip_tags
from datetime import timedelta
import random

from rest_framework import generics, permissions, status, parsers, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.exceptions import PermissionDenied

from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session, 
    Question, Choice, MockTest, MockTestQuestion
)
from .serializers import (
    UserSerializer, CourseRequestSerializer, StudyMaterialSerializer,
    MyTokenObtainPairSerializer, BranchSerializer, ChangePasswordSerializer,
    UserProfileSerializer,
    # New System Serializers
    QuestionBankSerializer, MockTestGeneratorSerializer,
    MockTestSessionSerializer, MockTestSubmitSerializer, MockTestResultSerializer,
    MockTestHistorySerializer
)

# --- EMAIL HELPER FUNCTION ---

def send_html_email(subject, recipient_email, username, otp, type='reset'):
    """
    Sends a professional HTML email with the Produit Academy logo.
    type: 'reset' | 'signup' | 'resend'
    """
    
    if type == 'reset':
        title = "Password Reset Request"
        intro = "We received a request to reset the password for your account."
    elif type == 'signup':
        title = "Welcome to Produit Academy!"
        intro = "Thank you for signing up. Please verify your email address to get started."
    else: # resend
        title = "New OTP Request"
        intro = "We received a request to resend your verification code."


    logo_url = "https://produit-academy-frontend.vercel.app/logo.png"
    
    message_body = f"""
                <p>Hi <strong>{username}</strong>,</p>
                <p>{intro}</p>
                <p>Your One-Time Password (OTP) is:</p>
                <div class="otp-box">{otp}</div>
                <p>This OTP will expire in 10 minutes for security reasons.</p>
                <p>If you did not request this, please ignore this email or contact support.</p>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 20px auto; padding: 30px; border: 1px solid #eee; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .logo {{ max-width: 120px; height: auto; }}
            .content {{ font-size: 16px; }}
            .otp-box {{ 
                background-color: #f0f7ff; 
                border: 1px dashed #0070f3;
                color: #0070f3;
                padding: 20px; 
                text-align: center; 
                font-size: 32px; 
                font-weight: bold; 
                letter-spacing: 8px; 
                margin: 25px 0; 
                border-radius: 8px; 
            }}
            .footer {{ margin-top: 40px; font-size: 12px; color: #888; text-align: center; border-top: 1px solid #eee; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="{logo_url}" alt="Produit Academy" class="logo">
            </div>
            
            <div class="content">
                <h2 style="text-align: center; color: #111;">{title}</h2>
                {message_body}
                <br>
                <p>Regards,<br><strong>Produit Academy Support Team</strong></p>
            </div>
            
            <div class="footer">
                &copy; {timezone.now().year} Produit Academy. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    plain_message = strip_tags(html_content)
    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [recipient_email],
        html_message=html_content,
        fail_silently=False,
    )

# --- AUTHENTICATION & SESSION MANAGEMENT ---

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            serializer = self.get_serializer(data=request.data)
            try:
                serializer.is_valid(raise_exception=True)
                user = serializer.user
                
                # Single Session Enforcement (STUDENTS ONLY)
                if user.role == 'student':
                    Session.objects.filter(user=user).delete()
                    session_key = response.data.get('access')
                    if session_key:
                        Session.objects.create(user=user, session_key=str(session_key))
                
                if user.is_superuser or user.is_staff:
                    response.data['role'] = 'admin'
                else:
                    response.data['role'] = user.role 
            except Exception:
                pass
        return response

class SignUpView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        user.student_id = f"PROD-{random.randint(1000, 9999)}"
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = timezone.now() + timedelta(minutes=10)
        user.save()

        if user.branch:
            if not CourseRequest.objects.filter(student=user, branch=user.branch).exists():
                CourseRequest.objects.create(student=user, branch=user.branch, status='Pending')

        try:
            send_html_email('Welcome to Produit Academy - Verify Email', user.email, user.username, otp, type='signup')
        except Exception as e:
            print(f"Email Error: {e}")

class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        try:
            user = User.objects.get(email=email)
            if user.otp == otp and user.otp_expiry > timezone.now():
                user.is_active = True
                user.is_verified = True
                user.otp = None
                user.save()
                return Response({'detail': 'Verified successfully!'})
            return Response({'detail': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_expiry = timezone.now() + timedelta(minutes=10)
            user.save()
            try:
                send_html_email('New Verification Code', user.email, user.username, otp, type='resend')
                return Response({'detail': 'OTP resent successfully'})
            except Exception:
                return Response({'detail': 'Failed to send email'}, status=500)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=404)

class ChangePasswordView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    def get_object(self):
        return self.request.user

class PasswordResetRequestOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_expiry = timezone.now() + timedelta(minutes=10)
            user.save()
            try:
                send_html_email('Password Reset Request', user.email, user.username, otp, type='reset')
                return Response({'detail': 'OTP sent'})
            except Exception:
                return Response({'detail': 'Failed to send email'}, status=500)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=404)

class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        password = request.data.get('password')
        try:
            user = User.objects.get(email=email)
            if user.otp == otp and user.otp_expiry > timezone.now():
                user.set_password(password)
                user.otp = None
                user.save()
                return Response({'detail': 'Password reset successful'})
            return Response({'detail': 'Invalid OTP'}, status=400)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=404)

# --- DASHBOARD & USER MANAGEMENT ---

class StudentDashboardView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer
    def get_object(self):
        return self.request.user

class AdminDashboardView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = CourseRequest.objects.filter(status='Pending')
    serializer_class = CourseRequestSerializer

class BranchListView(generics.ListAPIView):
    queryset = Branch.objects.all()
    serializer_class = BranchSerializer
    permission_classes = [permissions.AllowAny]

class ProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer
    def get_object(self):
        return self.request.user

class StudentListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.filter(role='student')
    serializer_class = UserSerializer

class StudentManageView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()

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

# ==========================================
#  NEW TESTING SYSTEM: ADMIN & STUDENT VIEWS
# ==========================================

# --- ADMIN: QUESTION BANK & CATEGORY MANAGEMENT ---



class AdminQuestionBankView(viewsets.ModelViewSet):
    """
    Admin ViewSet to Manage the Global Question Bank.
    Endpoint: /api/admin/questions/
    """
    permission_classes = [permissions.IsAdminUser]
    queryset = Question.objects.all().order_by('-created_at')
    serializer_class = QuestionBankSerializer

# --- STUDENT: CUSTOM MOCK TEST SYSTEM ---

class GenerateMockTestView(APIView):
    """
    Allows a student to generate a custom test based on:
    - Categories (e.g., Aptitude, Data Structures)
    - Number of Questions
    - Time Limit
    - Whether to repeat previously attempted questions
    """
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
            
            # Filter by Branch (if provided)
            # Note: General Aptitude usually has no branch, so we might want to handle that.
            # But the user logic is "aptitude no need of selecting branch... but math and other subjects select the branch"
            if branch_id:
                # If categories are provided, we only apply branch filter to non-Aptitude questions?
                # Actually simpler: The frontend sends branch_id. 
                # If we want GA questions (which have no branch), we might miss them if we strict filter branch_id=X.
                # So we should say: (branch_id=X OR category='General Aptitude')
                from django.db.models import Q
                questions_query = questions_query.filter(Q(branch_id=branch_id) | Q(category='General Aptitude'))

            # Filter by Category if provided
            if categories:
                questions_query = questions_query.filter(category__in=categories)
            
            # Filter by Attempt History if 'allow_repeats' is False
            if not allow_repeats:
                attempted_q_ids = MockTestQuestion.objects.filter(
                    mock_test__student=request.user
                ).values_list('question_id', flat=True)
                questions_query = questions_query.exclude(id__in=attempted_q_ids)

            # 3. Random Selection
            available_ids = list(questions_query.values_list('id', flat=True))
            
            if len(available_ids) < num_questions:
                return Response(
                    {
                        "error": f"Not enough questions available matching criteria. Found {len(available_ids)}, requested {num_questions}.",
                        "available_count": len(available_ids)
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            selected_ids = random.sample(available_ids, num_questions)
            
            # 4. Create Mock Test Session
            mock_test = MockTest.objects.create(
                student=request.user,
                total_questions=num_questions,
                time_limit_minutes=time_limit,
                is_completed=False
            )

            # 5. Link Questions to Test (Bulk Create for Efficiency)
            test_questions = []
            for index, q_id in enumerate(selected_ids):
                test_questions.append(MockTestQuestion(
                    mock_test=mock_test,
                    question_id=q_id,
                    order=index + 1
                ))
            MockTestQuestion.objects.bulk_create(test_questions)

            # 6. Return the Test Session Data (Hiding answers)
            return Response(MockTestSessionSerializer(mock_test).data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SubmitMockTestView(APIView):
    """
    Handles the submission of a mock test.
    Calculates the score immediately and marks the test as completed.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        mock_test = get_object_or_404(MockTest, pk=pk, student=request.user)

        if mock_test.is_completed:
            return Response({"error": "Test already submitted."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = MockTestSubmitSerializer(data=request.data)
        if serializer.is_valid():
            total_score = 0.0
            
            # Create a map of Question ID -> Selected Choice ID
            answers_map = {item['question_id']: item['choice_id'] for item in serializer.validated_data['answers']}
            
            # Fetch all questions for this test
            test_questions = MockTestQuestion.objects.filter(mock_test=mock_test).select_related('question')
            
            for tq in test_questions:
                # If user provided an answer for this question
                if tq.question.id in answers_map:
                    choice_id = answers_map[tq.question.id]
                    try:
                        # Verify the choice belongs to the question
                        selected_choice = Choice.objects.get(id=choice_id, question=tq.question)
                        tq.selected_choice = selected_choice
                        
                        if selected_choice.is_correct:
                            tq.is_correct = True
                            total_score += tq.question.marks
                            
                    except Choice.DoesNotExist:
                        pass # Invalid choice ID ignored
                
                tq.save()

            # Finalize Test
            mock_test.score = total_score
            mock_test.is_completed = True
            mock_test.completed_at = timezone.now()
            mock_test.save()

            return Response({
                "message": "Test submitted successfully",
                "score": total_score,
                "test_id": mock_test.id
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StudentMockTestHistoryView(generics.ListAPIView):
    """
    Lists all mock tests attempted by the student, ordered by newest first.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MockTestHistorySerializer

    def get_queryset(self):
        return MockTest.objects.filter(student=self.request.user).order_by('-created_at')

class AdminStudentHistoryView(generics.ListAPIView):
    """
    Allows ADMIN to view a specific student's test history
    """
    permission_classes = [permissions.IsAdminUser]
    serializer_class = MockTestHistorySerializer

    def get_queryset(self):
        student_id = self.kwargs['pk']
        return MockTest.objects.filter(student_id=student_id).order_by('-created_at')

class StudentMockTestAnalyticsView(generics.RetrieveAPIView):
    """
    Provides a detailed view of a specific test including:
    - User's answers vs Correct answers
    - Score breakdown by category
    
    Access is RESTRICTED to completed tests only.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MockTestResultSerializer
    queryset = MockTest.objects.all()

    def get_object(self):
        obj = super().get_object()
        # Security Check: User must own the test
        if obj.student != self.request.user:
            raise PermissionDenied("You do not have permission to view this test.")
        
        # Logic Check: Test must be finished to see answers
        if not obj.is_completed:
            raise PermissionDenied("You must complete the test to view analytics.")
        
        return obj