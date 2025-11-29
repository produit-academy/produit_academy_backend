from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.http import FileResponse, Http404
from django.utils.html import strip_tags
from datetime import timedelta
import random

from rest_framework import generics, permissions, status, parsers, views
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

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
    
    # Default message body for non-reset types
    message_body = f"""
                <p>Hi <strong>{username}</strong>,</p>
                
                <p>{intro}</p>
                
                <p>Your One-Time Password (OTP) is:</p>
                
                <div class="otp-box">{otp}</div>
                
                <p>This OTP will expire in 10 minutes for security reasons.</p>
                
                <p>If you did not request this, please ignore this email or contact support.</p>
    """

    # Specific message body for reset type as requested
    if type == 'reset':
        message_body = f"""
                <p>Hi <strong>{username}</strong>,</p>

                <p>We received a request to reset the password for your account.</p>

                <p>Your One-Time Password (OTP) is:</p>

                <div class="otp-box">{otp}</div>

                <p>This OTP will expire in 10 minutes for security reasons.</p>

                <p>If you did not request a password reset, please ignore this email or contact support.</p>
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
                
                # Single Session Enforcement (All Users)
                Session.objects.filter(user=user).delete()
                
                session_key = response.data.get('access')
                if session_key:
                    Session.objects.create(user=user, session_key=str(session_key))
                
                # Send role to frontend for redirection
                if user.is_superuser or user.is_staff:
                    response.data['role'] = 'admin'
                else:
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
            if not CourseRequest.objects.filter(student=user, branch=user.branch).exists():
                CourseRequest.objects.create(student=user, branch=user.branch, status='Pending')

        # Send Email
        try:
            send_html_email(
                'Welcome to Produit Academy - Verify Email',
                user.email,
                user.username,
                otp,
                type='signup'
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
            try:
                send_html_email(
                    'New Verification Code',
                    user.email,
                    user.username,
                    otp,
                    type='resend'
                )
                return Response({'detail': 'OTP resent successfully'})
            except Exception as e:
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
                send_html_email(
                    'Password Reset Request',
                    user.email,
                    user.username,
                    otp,
                    type='reset'
                )
                return Response({'detail': 'OTP sent'})
            except Exception as e:
                print(f"Email Error: {e}")
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

        is_approved = CourseRequest.objects.filter(
            student=user, 
            branch=user.branch, 
            status='Approved'
        ).exists()

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

# --- QUIZ & EXAM SYSTEM ---

class QuizCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Quiz.objects.all()
    serializer_class = QuizCreateSerializer

class StudentQuizListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSerializer

    def get_queryset(self):
        user = self.request.user
        if user.branch and CourseRequest.objects.filter(student=user, branch=user.branch, status='Approved').exists():
            return Quiz.objects.filter(branch=user.branch)
        return Quiz.objects.none()

class StudentQuizDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = QuizSerializer
    queryset = Quiz.objects.all()

    def get_object(self):
        obj = super().get_object()
        user = self.request.user
        
        has_approval = CourseRequest.objects.filter(
            student=user, 
            branch=user.branch, 
            status='Approved'
        ).exists()

        if not has_approval or obj.branch != user.branch:
            raise PermissionDenied("You do not have access to this quiz.")
        
        return obj

class QuizSubmitView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            quiz = Quiz.objects.get(pk=pk)
            user = request.user
            has_approval = CourseRequest.objects.filter(
                student=user, 
                branch=user.branch, 
                status='Approved'
            ).exists()

            if not has_approval or quiz.branch != user.branch:
                return Response({'error': 'You do not have permission to submit this quiz.'}, status=403)

            answers = request.data.get('answers', [])
            score = 0.0

            for ans in answers:
                try:
                    choice = Choice.objects.get(id=ans['choice_id'], question_id=ans['question_id'])
                    if choice.is_correct:
                        score += choice.question.marks
                except Choice.DoesNotExist:
                    continue
            
            QuizSubmission.objects.create(student=user, quiz=quiz, score=score)
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
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSerializer
    queryset = Quiz.objects.all().order_by('-created_at')

class AdminQuizDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizCreateSerializer
    queryset = Quiz.objects.all()

class AdminGlobalAnalyticsView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSubmissionDetailSerializer
    queryset = QuizSubmission.objects.all().order_by('-submitted_at')

class AdminStudentHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = QuizSubmissionDetailSerializer

    def get_queryset(self):
        student_id = self.kwargs['pk']
        return QuizSubmission.objects.filter(student_id=student_id).order_by('-submitted_at')