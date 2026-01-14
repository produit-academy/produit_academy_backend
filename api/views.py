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
    Question, Choice, MockTest, MockTestQuestion, Complaint, ContactInquiry
)
from .serializers import (
    UserSerializer, CourseRequestSerializer, StudyMaterialSerializer,
    MyTokenObtainPairSerializer, BranchSerializer, ChangePasswordSerializer,
    UserProfileSerializer,
    QuestionBankSerializer, MockTestGeneratorSerializer,
    MockTestSessionSerializer, MockTestSubmitSerializer, MockTestResultSerializer,
    MockTestHistorySerializer, ComplaintSerializer, ContactInquirySerializer
)

# --- EMAIL HELPER FUNCTION ---

def send_html_email(subject, recipient_email, username, otp, type='reset'): 
    if type == 'reset':
        title = "Password Reset Request"
        intro = "We received a request to reset the password for your account."
    elif type == 'signup':
        title = "Welcome to Produit Academy!"
        intro = "Thank you for signing up. Please verify your email address to get started."
    elif type == 'approval':
        title = "Course Request Approved!"
        intro = "Congratulations! Your request to join the course has been approved."
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
                    <a href="https://produit-academy-frontend.vercel.app/login" style="background-color: #0070f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Login to Dashboard</a>
                </div>
                <p>Good luck with your studies!</p>
        """
    else:
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
    queryset = CourseRequest.objects.filter(status='Pending', student__is_verified=True)
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
    queryset = User.objects.filter(role='student', is_active=True)
    serializer_class = UserSerializer

class StudentManageView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all()
    serializer_class = UserSerializer

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

from rest_framework.pagination import PageNumberPagination

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

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
                count_ga = int(num_questions * 0.15)
                count_math = int(num_questions * 0.15)
                count_core = num_questions - count_ga - count_math
                
                def get_category_ids(cat_name, target_count):
                    # We must use the base query (filtered by branch/type/repeats) but enforce category
                    cat_query = questions_query.filter(category=cat_name)
                    ids = list(cat_query.values_list('id', flat=True))
                    return random.sample(ids, min(len(ids), target_count))

                ids_ga = get_category_ids('General Aptitude', count_ga)
                ids_math = get_category_ids('Engineering Mathematics', count_math)
                ids_core = get_category_ids('Subject Paper', count_core)
                
                selected_ids = ids_ga + ids_math + ids_core
                
                # Fill remaining if any category was short on questions
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
    serializer_class = MockTestResultSerializer
    queryset = MockTest.objects.all()
    def get_object(self):
        obj = super().get_object()
        if obj.student != self.request.user:
            raise PermissionDenied("You do not have permission to view this test.")
        if not obj.is_completed:
            raise PermissionDenied("You must complete the test to view analytics.")
        return obj

# --- COMPLAINT SYSTEM VIEWS ---

class StudentComplaintView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ComplaintSerializer

    def get_queryset(self):
        return Complaint.objects.filter(student=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(student=self.request.user)

class AdminComplaintDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = ComplaintSerializer
    queryset = Complaint.objects.all()

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status == 'Resolved' and not instance.resolved_at:
            instance.resolved_at = timezone.now()
            instance.save()

class AdminComplaintListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = ComplaintSerializer
    queryset = Complaint.objects.all().order_by('-created_at')

class ContactInquiryView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    queryset = ContactInquiry.objects.all()
    serializer_class = ContactInquirySerializer

class AdminContactListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = ContactInquiry.objects.all().order_by('-created_at')
    serializer_class = ContactInquirySerializer

class AdminContactUpdateView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = ContactInquiry.objects.all()
    serializer_class = ContactInquirySerializer
