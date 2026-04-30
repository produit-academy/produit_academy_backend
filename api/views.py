from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.html import strip_tags
from datetime import timedelta
import random
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView


from .models import User, Branch, CourseRequest, Session
from .serializers import (
    UserSerializer, MyTokenObtainPairSerializer, BranchSerializer,
    ChangePasswordSerializer, UserProfileSerializer,
)

# --- EMAIL HELPER FUNCTION ---

def send_html_email(subject, recipient_email, username, otp=None, type='reset', **kwargs): 
    if type == 'reset':
        title = "Password Reset Request"
        intro = "We received a request to reset the password for your account."
    elif type == 'signup':
        title = "Welcome to Produit Academy!"
        intro = "Thank you for signing up. Please verify your email address to get started."
    elif type == 'approval':
        title = "Course Request Approved!"
        intro = "Congratulations! Your request to join the course has been approved."
    elif type == 'staff_otp':
        title = "Welcome to the Produit Academy Team!"
        intro = "We are thrilled to extend an offer for you to join our faculty."
    elif type == 'staff_welcome':
        title = "Contract Approved!"
        intro = f"Your account is now verified. You can log in using your email."
    elif type == 'demo_alert':
        title = "Action Required: Demo Link Needed"
        intro = f"You have a new Demo Class scheduled with {kwargs.get('student_name', 'a student')}. Please log in and provide a meeting link."
    elif type == 'demo_link':
        title = "Your Demo Class is Confirmed!"
        intro = f"Your Demo Class with {kwargs.get('teacher_name', 'your teacher')} is scheduled."
    elif type == 'mentor_demo_alert':
        title = "Demo Class Scheduled"
        intro = f"Your assigned student, {kwargs.get('student_name', 'a student')}, has a Demo Class scheduled."
    else: # resend
        title = "New OTP Request"
        intro = "We received a request to resend your verification code."


    logo_url = "https://produit-academy-frontend.vercel.app/logo.png"
    
    if type == 'approval':
        message_body = f"""
                <p>Hi <strong>{username}</strong>,</p>
                <p>{intro}</p>
                <p>You can now log in and access your dashboard to start learning.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="https://gate.produitacademy.com/login" style="background-color: #0070f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Login to Dashboard</a>
                </div>
                <p>Good luck with your studies!</p>
        """
    elif type == 'staff_otp' and otp:
        message_body = f"""
                    <p>Dear <strong>{username}</strong>,</p>
                    <p>We are thrilled to officially invite you to join the Produit Academy team! Your expertise will be invaluable in shaping the futures of our students.</p>
                    
                    <div style="background-color: #f8fafc; border-left: 4px solid #0070f3; padding: 15px 20px; margin: 25px 0; border-radius: 0 8px 8px 0;">
                        <h3 style="margin-top: 0; color: #111; font-size: 16px;">What's included in this Agreement?</h3>
                        <ul style="margin-bottom: 0; padding-left: 20px; font-size: 14px; color: #444;">
                            <li style="margin-bottom: 8px;"><strong>Role Commitment:</strong> Agreement to provide high-quality, dedicated teaching or mentorship services to your assigned students.</li>
                            <li style="margin-bottom: 8px;"><strong>Platform Guidelines:</strong> Adherence to Produit Academy's teaching standards, code of conduct, and operational workflows.</li>
                            <li style="margin-bottom: 8px;"><strong>Confidentiality:</strong> Protection of student data and our proprietary educational materials.</li>
                            <li><strong>Terms & Privacy:</strong> Acceptance of our standard Terms of Service and Privacy Policy.</li>
                        </ul>
                    </div>
                    
                    <p>To finalize your onboarding and sign the digital contract, please visit the <a href="https://produitacademy.com/agreement" style="color: #0070f3; font-weight: bold; text-decoration: none;">Agreement Portal</a> and enter the secure Verification Code (OTP) below:</p>
                    
                    <div class="otp-box">{otp}</div>
                    
                    <p>This code will expire in 7 days. Once signed, your account will be sent to HR for final approval and activation.</p>
                    <p>If you have any questions before signing, please reply directly to this email.</p>
        """
    elif type in ['reset', 'signup', 'resend'] and otp:
        message_body = f"""
                    <p>Hi <strong>{username}</strong>,</p>
                    <p>{intro}</p>
                    <p>Your One-Time Password (OTP) is:</p>
                    <div class="otp-box">{otp}</div>
                    <p>This OTP will expire in 10 minutes for security reasons.</p>
                    <p>If you did not request this, please ignore this email or contact support.</p>
        """
    elif type == 'demo_link':
        message_body = f"""
                    <p>Hi <strong>{username}</strong>,</p>
                    <p>{intro}</p>
                    <p><strong>Time:</strong> {kwargs.get('time', 'TBA')}</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{kwargs.get('link', '#')}" style="background-color: #0070f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Join Class</a>
                    </div>
                    <p>Please log in 5 minutes early.</p>
        """
    elif type == 'mentor_demo_alert':
        message_body = f"""
                    <p>Hi <strong>{username}</strong>,</p>
                    <p>{intro}</p>
                    <p><strong>Time:</strong> {kwargs.get('time', 'TBA')}</p>
                    <p>Log in to your mentor dashboard to view the session.</p>
        """
    else:
        message_body = f"""
                    <p>Hi <strong>{username}</strong>,</p>
                    <p>{intro}</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://produitacademy.com/login" style="background-color: #0070f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Log In Now</a>
                    </div>
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
                if user.role == 'student' and not user.is_staff and not user.is_superuser:
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

class VerifyAgreementView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        try:
            user = User.objects.get(email=email, role__in=['teacher', 'mentor'])
            if user.otp == otp and user.otp_expiry and user.otp_expiry > timezone.now():
                user.otp = None
                user.save()
                return Response({'message': 'Agreement signed successfully. Pending HR approval.'})
            return Response({'error': 'Invalid or expired OTP.'}, status=400)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)

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
    def get_queryset(self):
        from gate.serializers import CourseRequestSerializer
        return CourseRequest.objects.filter(status='Pending', student__is_verified=True)
    def get_serializer_class(self):
        from gate.serializers import CourseRequestSerializer
        return CourseRequestSerializer

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
    queryset = User.objects.filter(role='student', is_active=True)
    serializer_class = UserSerializer

class StudentManageView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all()
    serializer_class = UserSerializer