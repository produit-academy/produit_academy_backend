from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.http import FileResponse, Http404
from datetime import timedelta
import random

from rest_framework import generics, permissions, status, parsers, views
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.exceptions import AuthenticationFailed

from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session, 
    Quiz, Question, Choice, QuizSubmission
)
from .serializers import (
    UserSerializer, CourseRequestSerializer, StudyMaterialSerializer,
    MyTokenObtainPairSerializer, BranchSerializer, ChangePasswordSerializer,
    UserProfileSerializer, QuizSerializer, QuizCreateSerializer, 
    QuizSubmissionDetailSerializer
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
                
                Session.objects.filter(user=user).delete()
                session_key = response.data.get('access')
                if session_key:
                    Session.objects.create(user=user, session_key=str(session_key))
                
                response.data['role'] = user.role 

            except Exception as e:
                pass
        return response

class SignUpView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        
        # Student ID Generation
        user.student_id = f"PROD-{random.randint(1000, 9999)}"
        
        # OTP Generation
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = timezone.now() + timedelta(minutes=10)
        user.save()

        # Auto-create Course Request if branch selected
        if user.branch:
            CourseRequest.objects.create(student=user, branch=user.branch, status='Pending')

        # Send Email
        try:
            send_mail(
                'Verify your Email - Produit Academy',
                f'Welcome {user.username}!\nYour OTP is: {otp}\nIt expires in 10 minutes.',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
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
            send_mail('New OTP', f'Your new OTP is: {otp}', settings.EMAIL_HOST_USER, [user.email])
            return Response({'detail': 'OTP resent successfully'})
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
            send_mail('Reset Password OTP', f'Your OTP is: {otp}', settings.EMAIL_HOST_USER, [user.email])
            return Response({'detail': 'OTP sent'})
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
        instance.is_active = False # Soft delete
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
        try:
            req = CourseRequest.objects.filter(student=user).latest('id')
            if req.status == 'Approved':
                return StudyMaterial.objects.filter(branch=req.branch)
            return StudyMaterial.objects.filter(branch=req.branch, is_preview=True)
        except CourseRequest.DoesNotExist:
            return StudyMaterial.objects.none()

class StudyMaterialUploadView(generics.CreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]
    queryset = StudyMaterial.objects.all()
    serializer_class = StudyMaterialSerializer

class MaterialFileView(APIView):
    permission_classes = [permissions.AllowAny] # Controlled via signed URLs ideally, but open for MVP
    def get(self, request, pk):
        try:
            material = StudyMaterial.objects.get(pk=pk)
            response = FileResponse(material.file.open(), content_type='application/pdf')
            # 'inline' allows displaying in browser/React-PDF instead of downloading
            response['Content-Disposition'] = f'inline; filename="{material.file.name}"'
            return response
        except StudyMaterial.DoesNotExist:
            raise Http404

# --- QUIZ & EXAM SYSTEM ---

class QuizCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Quiz.objects.all()
    serializer_class = QuizCreateSerializer

class StudentQuizDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSerializer
    queryset = Quiz.objects.all()

class QuizSubmitView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            quiz = Quiz.objects.get(pk=pk)
            answers = request.data.get('answers', [])
            score = 0.0

            for ans in answers:
                try:
                    choice = Choice.objects.get(id=ans['choice_id'], question_id=ans['question_id'])
                    if choice.is_correct:
                        score += choice.question.marks
                    # Optional: Add negative marking logic here
                except Choice.DoesNotExist:
                    continue
            
            QuizSubmission.objects.create(student=request.user, quiz=quiz, score=score)
            return Response({'score': score, 'message': 'Quiz Submitted Successfully'})
        except Quiz.DoesNotExist:
            return Response({'error': 'Quiz not found'}, status=404)

class StudentAnalyticsListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSubmissionDetailSerializer
    def get_queryset(self):
        return QuizSubmission.objects.filter(student=self.request.user).order_by('-submitted_at')

class StudentResultDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSubmissionDetailSerializer
    queryset = QuizSubmission.objects.all()

class AdminQuizListView(generics.ListAPIView):
    """List all quizzes for the Admin Dashboard"""
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSerializer
    queryset = Quiz.objects.all().order_by('-created_at')

class AdminQuizDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Edit or Delete a specific quiz"""
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizCreateSerializer
    queryset = Quiz.objects.all()

class AdminGlobalAnalyticsView(generics.ListAPIView):
    """View all student submissions for the Admin"""
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSubmissionDetailSerializer
    queryset = QuizSubmission.objects.all().order_by('-submitted_at')

class StudentQuizListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSerializer

    def get_queryset(self):
        # Only show quizzes relevant to the student's branch
        user = self.request.user
        if user.branch:
            return Quiz.objects.filter(branch=user.branch)
        return Quiz.objects.none()
    
class AdminStudentHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSubmissionDetailSerializer

    def get_queryset(self):
        student_id = self.kwargs['pk']
        return QuizSubmission.objects.filter(student_id=student_id).order_by('-submitted_at')