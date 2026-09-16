from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.utils import timezone
from django.db import models as db_models
from api.models import (
    User, Branch, Department, StaffProfile, StaffTask, TaskComment,
    Complaint, ContactInquiry, StaffWallet, WalletTransaction,
    TaskSubmissionHistory, TaskPaymentAuditLog
)
from classes_app.models import Course, TeacherProfile, Subject, Booking, ClassSession
from gate.models import MockTest, Question, StudyMaterial, CourseRequest
from careers.models import JobApplication
from api.views import send_html_email
import random
import string
import re
from decimal import Decimal
from datetime import timedelta
from .serializers import (
    DepartmentSerializer, StaffProfileSerializer,
    StaffTaskSerializer, TaskCommentSerializer,
    SuperAdminUserSerializer, StaffWalletSerializer,
    WalletTransactionSerializer, ManagerStaffSerializer,
    TaskSubmissionHistorySerializer, TaskPaymentAuditLogSerializer,
)
from .permissions import HasModuleAccess


def is_admin(user):
    """Check if user is an admin — either by role field or Django is_staff flag."""
    return user.role == 'admin' or user.is_staff or user.is_superuser


def is_manager(user):
    """Check if user is a manager."""
    return user.role == 'manager'


def is_admin_or_manager(user):
    """Check if user is admin or manager."""
    return is_admin(user) or is_manager(user)


AVAILABLE_MODULES = [
    {'key': 'support', 'label': 'Support', 'description': 'Complaints & Contact Inquiries'},
    {'key': 'careers', 'label': 'Careers', 'description': 'Job Applications'},
    {'key': 'gate_content', 'label': 'GATE Content', 'description': 'Questions & Study Materials'},
    {'key': 'classes', 'label': 'Classes', 'description': 'Courses, Enrollments, Attendance'},
    {'key': 'analytics', 'label': 'Analytics', 'description': 'Dashboard Stats & Reports'},
]


# ============================================================
# SUPER ADMIN Cross-Platform User Management
# ============================================================

class SuperAdminUserListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SuperAdminUserSerializer

    def get_queryset(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied('Only super admins can access this.')
            
        queryset = User.objects.exclude(role='student').order_by('-date_joined')
        
        # Exclude unapproved teachers and mentors
        queryset = queryset.exclude(role='teacher', classes_teacher_profile__is_approved=False)
        
        platform = self.request.query_params.get('platform')
        if platform:
            if platform == 'staff':
                queryset = queryset.filter(role='staff')
            else:
                queryset = queryset.filter(platform=platform)
        role = self.request.query_params.get('role')
        if role:
            queryset = queryset.filter(role=role)
        return queryset


class SuperAdminUserCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not request.user.is_superuser:
            return Response({'error': 'Only super admins can create users.'}, status=403)

        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        phone_number = request.data.get('phone_number', '')
        account_type = request.data.get('account_type', 'platform_admin')

        if not email:
            return Response({'error': 'Email is required.'}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'A user with this email already exists.'}, status=400)

        # Auto-generate random secure password if not explicitly supplied
        raw_password = password.strip() if password and str(password).strip() else ('PA-' + ''.join(random.choices(string.ascii_letters + string.digits, k=10)))

        valid_types = ['platform_admin', 'support_staff', 'contact_staff', 'hr_staff', 'manager', 'custom_staff']
        if account_type not in valid_types:
            return Response({'error': 'Invalid account type.'}, status=400)

        login_url = 'https://staff.produitacademy.com/login'
        platform_label = 'Staff Portal'

        if account_type == 'platform_admin':
            platform = request.data.get('platform', 'gate')
            user = User.objects.create_user(
                username=email, email=email, password=raw_password,
                first_name=first_name, last_name=last_name,
                phone_number=phone_number, role='admin', platform=platform,
                is_verified=True, is_staff=True,
            )
            login_url = f'https://{platform}.produitacademy.com/login'
            platform_label = f'{platform.upper()} Admin'
            label = f'{platform.upper()} admin'

        elif account_type == 'manager':
            user = User.objects.create_user(
                username=email, email=email, password=raw_password,
                first_name=first_name, last_name=last_name,
                phone_number=phone_number, role='manager', is_verified=True,
            )
            StaffProfile.objects.create(user=user, designation='Manager')
            label = 'Manager'

        else:
            user = User.objects.create_user(
                username=email, email=email, password=raw_password,
                first_name=first_name, last_name=last_name,
                phone_number=phone_number, role='staff', is_verified=True,
            )

            if account_type == 'support_staff':
                platforms = request.data.get('assigned_platforms', ['gate'])
                dept_name = f"Support - {', '.join([p.upper() for p in platforms])}"
                dept, _ = Department.objects.get_or_create(
                    name=dept_name,
                    defaults={'allowed_modules': ['support'], 'description': f'Support staff for {dept_name}'}
                )
                StaffProfile.objects.create(user=user, department=dept, designation='Support Staff')
                label = 'Support staff'

            elif account_type == 'contact_staff':
                platforms = request.data.get('assigned_platforms', ['gate'])
                dept_name = f"Contact - {', '.join([p.upper() for p in platforms])}"
                dept, _ = Department.objects.get_or_create(
                    name=dept_name,
                    defaults={'allowed_modules': ['support'], 'description': f'Contact enquiry staff for {dept_name}'}
                )
                StaffProfile.objects.create(user=user, department=dept, designation='Contact Enquiry Staff')
                label = 'Contact enquiry staff'

            elif account_type == 'hr_staff':
                dept, _ = Department.objects.get_or_create(
                    name='HR - Careers',
                    defaults={'allowed_modules': ['careers', 'classes'], 'description': 'HR staff for job application reviews and onboarding'}
                )
                StaffProfile.objects.create(user=user, department=dept, designation='HR Staff')
                label = 'HR staff'

            elif account_type == 'custom_staff':
                dept_name = request.data.get('department_name', 'General')
                designation = request.data.get('designation', 'Staff')
                modules = request.data.get('modules', [])
                dept, _ = Department.objects.get_or_create(
                    name=dept_name,
                    defaults={'allowed_modules': modules, 'description': f'Custom department: {dept_name}'}
                )
                StaffProfile.objects.create(user=user, department=dept, designation=designation)
                label = f'{designation}'

        # Send welcome email with generated credentials
        email_sent = False
        try:
            display_name = f"{first_name} {last_name}".strip() or email.split('@')[0]
            send_html_email(
                f"Your {platform_label} Account is Ready",
                user.email,
                display_name,
                type='user_credentials',
                password=raw_password,
                login_url=login_url,
                platform_name=platform_label
            )
            email_sent = True
        except Exception as e:
            pass

        return Response({
            'message': f'{label} account created and login credentials emailed.',
            'user_id': user.id,
            'email': user.email,
            'email_sent': email_sent
        }, status=201)


class SuperAdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SuperAdminUserSerializer

    def get_object(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied('Only super admins can access this.')
        try:
            return User.objects.get(pk=self.kwargs['pk'])
        except User.DoesNotExist:
            raise NotFound('User not found.')

    def perform_destroy(self, instance):
        if instance == self.request.user:
            raise PermissionDenied('You cannot delete your own account.')
        instance.delete()


# ============================================================
# DEPARTMENT MANAGEMENT
# ============================================================

class AvailableModulesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not is_admin(request.user):
            raise PermissionDenied('Only admins can access this.')
        return Response(AVAILABLE_MODULES)


class DepartmentListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DepartmentSerializer
    queryset = Department.objects.all().order_by('name')

    def perform_create(self, serializer):
        if not is_admin(self.request.user):
            raise PermissionDenied('Only admins can create departments.')
        serializer.save()


class DepartmentDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DepartmentSerializer
    queryset = Department.objects.all()

    def perform_update(self, serializer):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        serializer.save()

    def perform_destroy(self, instance):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        instance.delete()


# ============================================================
# STAFF ACCOUNT MANAGEMENT
# ============================================================

class StaffSignUpView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not is_admin(request.user):
            return Response({'error': 'Only admins can create staff accounts'}, status=403)

        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=400)

        user = User.objects.create_user(
            username=email, email=email, password=password,
            first_name=request.data.get('first_name', ''),
            last_name=request.data.get('last_name', ''),
            phone_number=request.data.get('phone_number', ''),
            role='staff', is_verified=True,
        )

        profile_data = {'user': user, 'designation': request.data.get('designation', '')}
        department_id = request.data.get('department')
        if department_id:
            try:
                profile_data['department'] = Department.objects.get(pk=department_id)
            except Department.DoesNotExist:
                pass
        StaffProfile.objects.create(**profile_data)

        return Response({'message': 'Staff account created', 'user_id': user.id, 'email': user.email}, status=201)
# ============================================================
# HR ONBOARDING FOR CLASSES STAFF
# ============================================================

HR_FROM_EMAIL = 'Produit Academy HR <hr@produitacademy.com>'


class OnboardStaffView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Only HR and admins can view staff.'}, status=403)

        staff = User.objects.filter(
            platform='classes', role__in=['teacher']
        ).order_by('-date_joined')

        def _get_staff_approved(u):
            if u.role == 'teacher':
                return getattr(getattr(u, 'classes_teacher_profile', None), 'is_approved', False)
            return False

        def _get_staff_hourly_rate(u):
            if u.role == 'teacher':
                return getattr(getattr(u, 'classes_teacher_profile', None), 'hourly_rate', 0)
            return 0

        teacher_profiles = {}
        for tp in TeacherProfile.objects.filter(
            user__in=staff
        ).prefetch_related('taught_subjects').select_related('user'):
            teacher_profiles[tp.user_id] = list(tp.taught_subjects.values('id', 'name'))

        data = [{
            'id': u.id,
            'email': u.email,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'phone_number': u.phone_number or '',
            'role': u.role,
            'is_verified': u.is_verified,
            'is_active': u.is_active,
            'date_joined': u.date_joined.isoformat(),
            'has_signed': u.otp is None,  # OTP cleared = agreement signed
            'is_approved': _get_staff_approved(u),
            'hourly_rate': _get_staff_hourly_rate(u),
            'subjects': teacher_profiles.get(u.id, []),
        } for u in staff]

        return Response(data)

    def post(self, request):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Only HR and admins can onboard staff.'}, status=403)

        email = request.data.get('email')
        role = request.data.get('role') # 'teacher'
        subjects = request.data.get('subjects', []) # list of course IDs
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        phone_number = request.data.get('phone_number', '')
        hourly_rate = request.data.get('hourly_rate', 0)

        if not email or role not in ['teacher']:
            return Response({'error': 'Valid email and role (teacher) required.'}, status=400)
            
        if User.objects.filter(email=email).exists():
            return Response({'error': 'User already exists.'}, status=400)

        otp = str(random.randint(100000, 999999))
        user = User.objects.create_user(
            username=email, email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            role=role, platform='classes',
            is_verified=False,
            otp=otp,
            otp_expiry=timezone.now() + timedelta(days=7)
        )
        
        if role == 'teacher':
            profile = TeacherProfile.objects.create(user=user, hourly_rate=hourly_rate)
            if subjects:
                subs = Subject.objects.filter(id__in=subjects)
                profile.taught_subjects.set(subs)
                # Also add the parent courses to profile.subjects
                course_ids = subs.values_list('course_id', flat=True).distinct()
                profile.subjects.set(Course.objects.filter(id__in=course_ids))
                
        email_error = None
        try:
            send_html_email(
                'Welcome to Produit Academy Classes',
                user.email,
                f"{first_name} {last_name}".strip() or user.email.split('@')[0],
                otp,
                type='staff_otp',
                from_email=HR_FROM_EMAIL,
            )
        except Exception as e:
            email_error = str(e)
            
        return Response({
            'message': f'{role.capitalize()} onboarded successfully.',
            'user_id': user.id,
            'email_error': email_error
        }, status=201)


class OnboardStaffDetailView(APIView):
    """Edit or delete an onboarded teacher/mentor."""
    permission_classes = [IsAuthenticated]

    def get_staff_user(self, pk):
        try:
            return User.objects.get(pk=pk, platform='classes', role__in=['teacher'])
        except User.DoesNotExist:
            return None

    def patch(self, request, pk):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Permission denied.'}, status=403)

        user = self.get_staff_user(pk)
        if not user:
            return Response({'error': 'Staff member not found.'}, status=404)

        # Update user fields
        for field in ['first_name', 'last_name', 'phone_number', 'email']:
            if field in request.data:
                setattr(user, field, request.data[field])
        user.save()

        # Update subjects if teacher
        if user.role == 'teacher' and 'subjects' in request.data:
            profile, _ = TeacherProfile.objects.get_or_create(user=user)
            subs = Subject.objects.filter(id__in=request.data['subjects'])
            profile.taught_subjects.set(subs)
            course_ids = subs.values_list('course_id', flat=True).distinct()
            profile.subjects.set(Course.objects.filter(id__in=course_ids))

        if 'hourly_rate' in request.data:
            if user.role == 'teacher':
                profile, _ = TeacherProfile.objects.get_or_create(user=user)
                profile.hourly_rate = request.data['hourly_rate']
                profile.save()

        return Response({'message': 'Staff details updated successfully.'})

    def delete(self, request, pk):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Permission denied.'}, status=403)

        user = self.get_staff_user(pk)
        if not user:
            return Response({'error': 'Staff member not found.'}, status=404)

        user.delete()
        return Response({'message': 'Staff member deleted successfully.'})


class ApproveStaffView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Only HR and admins can approve staff.'}, status=403)
            
        user_id = request.data.get('user_id')
        try:
            user = User.objects.get(id=user_id, role__in=['teacher'])
            is_newly_verified = False
            if not user.is_verified:
                # Generate random password
                raw_password = 'PA-' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                user.set_password(raw_password)
                user.is_verified = True
                user.save()
                is_newly_verified = True
            
            if user.role == 'teacher':
                profile, _ = TeacherProfile.objects.get_or_create(user=user)
                if profile.is_approved:
                    return Response({'error': 'Teacher already approved.'}, status=400)
                profile.is_approved = True
                profile.save()
            
            if is_newly_verified:
                display_name = f"{user.first_name} {user.last_name}".strip() or user.email.split('@')[0]
                try:
                    send_html_email(
                        'Your Produit Academy Account is Ready!',
                        user.email,
                        display_name,
                        type='staff_credentials',
                        from_email=HR_FROM_EMAIL,
                        password=raw_password,
                    )
                except Exception:
                    pass
                return Response({'message': 'Staff approved. Login credentials sent via email.'})
            
            return Response({'message': 'Staff approval reinstated.'})
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)

class RevokeStaffView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Only HR and admins can revoke staff approval.'}, status=403)
            
        user_id = request.data.get('user_id')
        try:
            user = User.objects.get(id=user_id, role__in=['teacher'])
            if user.role == 'teacher':
                profile, _ = TeacherProfile.objects.get_or_create(user=user)
                profile.is_approved = False
                profile.save()
            
            return Response({'message': 'Staff approval revoked.'})
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)

# ============================================================
# STAFF SELF-SERVICE
# ============================================================

class StaffProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffProfileSerializer

    def get_object(self):
        if self.request.user.role not in ['staff', 'manager']:
            raise PermissionDenied('Only staff/managers can access this.')
        profile, _ = StaffProfile.objects.get_or_create(user=self.request.user)
        return profile

    def patch(self, request, *args, **kwargs):
        profile = self.get_object()
        serializer = StaffProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class StaffChangePasswordView(APIView):
    """Staff and managers can change their password from profile."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password', '').strip()
        new_password = request.data.get('new_password', '').strip()
        confirm_password = request.data.get('confirm_password', '').strip()

        if not current_password or not new_password:
            return Response({'error': 'Current password and new password are required.'}, status=400)

        if not user.check_password(current_password):
            return Response({'error': 'Current password is incorrect.'}, status=400)

        if len(new_password) < 6:
            return Response({'error': 'New password must be at least 6 characters long.'}, status=400)

        if confirm_password and new_password != confirm_password:
            return Response({'error': 'New passwords do not match.'}, status=400)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully.'})


class StaffMyModulesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Admins and managers see all modules
        if is_admin(user) or is_manager(user):
            return Response({'department': None, 'modules': AVAILABLE_MODULES})
        if user.role != 'staff':
            raise PermissionDenied('Only staff can access this.')
        try:
            profile = user.staff_profile
            dept = profile.department
            if not dept:
                return Response({'department': None, 'modules': []})
            accessible = [m for m in AVAILABLE_MODULES if m['key'] in (dept.allowed_modules or [])]
            return Response({'department': DepartmentSerializer(dept).data, 'modules': accessible})
        except StaffProfile.DoesNotExist:
            return Response({'department': None, 'modules': []})


class StaffTaskListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        user = self.request.user
        if user.role not in ['staff', 'manager']:
            raise PermissionDenied()
        return StaffTask.objects.filter(assigned_to=user).order_by('-created_at')


class StaffTaskUpdateView(generics.UpdateAPIView):
    """Staff updates their assigned task status (e.g., in_progress)."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        user = self.request.user
        if user.role not in ['staff', 'manager']:
            raise PermissionDenied()
        return StaffTask.objects.filter(assigned_to=user)


class StaffTaskSubmitCompletionView(APIView):
    """Staff submits task completion proof (text report, PDF file, image, time spent). Moves task to submitted_for_review."""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request, pk):
        user = request.user
        try:
            task = StaffTask.objects.get(pk=pk, assigned_to=user)
        except StaffTask.DoesNotExist:
            return Response({'error': 'Task not found or not assigned to you.'}, status=404)

        report = request.data.get('submission_report', '').strip()
        time_spent_raw = request.data.get('time_spent_hours', 0)
        try:
            time_spent = Decimal(str(time_spent_raw))
        except Exception:
            time_spent = Decimal('0.00')

        if not report and 'submission_file' not in request.FILES:
            return Response({'error': 'Please provide a completion description or upload a proof document.'}, status=400)

        task.submission_report = report
        task.time_spent_hours = time_spent
        task.submitted_at = timezone.now()
        task.status = 'submitted_for_review'

        if 'submission_file' in request.FILES:
            task.submission_file = request.FILES['submission_file']
        if 'submission_image' in request.FILES:
            task.submission_image = request.FILES['submission_image']

        task.save()

        # Add to history
        TaskSubmissionHistory.objects.create(
            task=task,
            submitted_by=user,
            submission_report=report,
            submission_file=task.submission_file,
            submission_image=task.submission_image,
            time_spent_hours=time_spent
        )

        return Response({
            'message': 'Task submitted for review successfully.',
            'task': StaffTaskSerializer(task).data
        })


class TaskCommentView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskCommentSerializer

    def get_queryset(self):
        task_id = self.kwargs['pk']
        user = self.request.user
        if user.role in ['staff', 'manager']:
            if not StaffTask.objects.filter(pk=task_id, assigned_to=user).exists():
                raise PermissionDenied()
        elif not is_admin(user):
            raise PermissionDenied()
        return TaskComment.objects.filter(task_id=task_id).order_by('created_at')

    def perform_create(self, serializer):
        task_id = self.kwargs['pk']
        user = self.request.user
        if user.role in ['staff', 'manager']:
            task = StaffTask.objects.filter(pk=task_id, assigned_to=user).first()
        elif is_admin(user):
            task = StaffTask.objects.filter(pk=task_id).first()
        else:
            raise PermissionDenied()
        if not task:
            raise NotFound()
        serializer.save(author=user, task=task)


# ============================================================
# STAFF MODULE ACCESS: Support
# ============================================================

def _get_staff_platforms(user):
    """Extract assigned platforms from staff department name (e.g. 'Support - GATE, CLASSES' → ['gate', 'classes'])."""
    if is_admin(user) or is_manager(user):
        return None  # Admins/managers see everything
    try:
        dept_name = user.staff_profile.department.name
        match = re.search(r'-\s*(.+)$', dept_name)
        if match:
            platforms = [p.strip().lower() for p in match.group(1).split(',')]
            return platforms
    except Exception:
        pass
    return None


class StaffComplaintListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'support'

    def get_queryset(self):
        queryset = Complaint.objects.all().order_by('-created_at')
        platforms = _get_staff_platforms(self.request.user)
        if platforms:
            queryset = queryset.filter(student__platform__in=platforms)
        # Allow explicit platform filter via query param
        platform_param = self.request.query_params.get('platform')
        if platform_param in ('gate', 'classes'):
            queryset = queryset.filter(student__platform=platform_param)
        return queryset

    def get_serializer_class(self):
        from support.serializers import ComplaintSerializer
        return ComplaintSerializer


class StaffComplaintDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'support'
    queryset = Complaint.objects.all()

    def get_serializer_class(self):
        from support.serializers import ComplaintSerializer
        return ComplaintSerializer

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status == 'Resolved' and not instance.resolved_at:
            instance.resolved_at = timezone.now()
            instance.save()


class StaffContactListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'support'

    def get_queryset(self):
        queryset = ContactInquiry.objects.all().order_by('-created_at')
        platforms = _get_staff_platforms(self.request.user)
        if platforms:
            queryset = queryset.filter(platform__in=platforms)
        # Also allow explicit query param override for admins
        platform = self.request.query_params.get('platform')
        if platform:
            queryset = queryset.filter(platform=platform)
        return queryset

    def get_serializer_class(self):
        from support.serializers import ContactInquirySerializer
        return ContactInquirySerializer


class StaffContactUpdateView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'support'
    queryset = ContactInquiry.objects.all()

    def get_serializer_class(self):
        from support.serializers import ContactInquirySerializer
        return ContactInquirySerializer

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status == 'Resolved' and not instance.resolved_at:
            instance.resolved_at = timezone.now()
            instance.save()


# ============================================================
# STAFF MODULE ACCESS: Careers
# ============================================================

class StaffJobApplicationListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'careers'

    def get_queryset(self):
        from careers.models import JobApplication
        return JobApplication.objects.all().order_by('-created_at')

    def get_serializer_class(self):
        from careers.serializers import JobApplicationSerializer
        return JobApplicationSerializer


class StaffJobApplicationUpdateView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, HasModuleAccess]
    module_key = 'careers'

    def get_queryset(self):
        from careers.models import JobApplication
        return JobApplication.objects.all()

    def get_serializer_class(self):
        from careers.serializers import JobApplicationSerializer
        return JobApplicationSerializer

# ============================================================
# ADMIN STAFF MANAGEMENT
# ============================================================

class AdminStaffListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffProfileSerializer

    def get_queryset(self):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        queryset = StaffProfile.objects.select_related('user', 'department').all()
        department_id = self.request.query_params.get('department')
        if department_id:
            queryset = queryset.filter(department_id=department_id)
        return queryset


class AdminStaffDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffProfileSerializer

    def get_object(self):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        try:
            return StaffProfile.objects.select_related('user', 'department').get(pk=self.kwargs['pk'])
        except StaffProfile.DoesNotExist:
            raise NotFound()


class AdminTaskCreateView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def perform_create(self, serializer):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        task = serializer.save(
            assigned_by=self.request.user,
            status='assigned',
            payment_status='not_assigned'
        )
        try:
            due_str = task.due_date.strftime('%b %d, %Y') if task.due_date else 'Flexible'
            send_html_email(
                f"New Task Assigned: {task.title}",
                task.assigned_to.email,
                task.assigned_to.first_name or task.assigned_to.username,
                type='task_assigned',
                task_title=task.title,
                task_description=task.description or '',
                due_date=due_str,
                assigned_by_name=f"{self.request.user.first_name} {self.request.user.last_name}".strip() or self.request.user.email
            )
        except Exception:
            pass


class AdminTaskListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        staff_id = self.request.query_params.get('staff_id')
        if staff_id:
            return StaffTask.objects.filter(assigned_to_id=staff_id).order_by('-created_at')
        return StaffTask.objects.all().order_by('-created_at')


class AdminTaskDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_object(self):
        if not is_admin(self.request.user):
            raise PermissionDenied()
        try:
            return StaffTask.objects.get(pk=self.kwargs['pk'])
        except StaffTask.DoesNotExist:
            raise NotFound()


# ============================================================
# STAFF WALLET (Self-service)
# ============================================================

class StaffWalletView(APIView):
    """Staff views their own wallet and transactions."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role not in ['staff', 'manager', 'teacher']:
            raise PermissionDenied('Only staff/teachers can view their wallet.')
        wallet, _ = StaffWallet.objects.get_or_create(staff=request.user)
        serializer = StaffWalletSerializer(wallet)
        return Response(serializer.data)


# ============================================================
# MANAGER VIEWS
# ============================================================

class ManagerStaffListView(generics.ListAPIView):
    """Manager sees all staff, teachers, and mentors."""
    permission_classes = [IsAuthenticated]
    serializer_class = ManagerStaffSerializer

    def get_queryset(self):
        if not is_manager(self.request.user) and not is_admin(self.request.user):
            raise PermissionDenied('Only managers and admins can view all staff.')
        queryset = User.objects.filter(
            role__in=['staff', 'manager', 'teacher']
        ).exclude(id=self.request.user.id).order_by('-date_joined')
        role = self.request.query_params.get('role')
        if role:
            queryset = queryset.filter(role=role)
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                db_models.Q(email__icontains=search) |
                db_models.Q(first_name__icontains=search) |
                db_models.Q(last_name__icontains=search)
            )
        return queryset


class ManagerTaskCreateView(generics.CreateAPIView):
    """Manager creates and assigns tasks (Postpaid model, no prepaid required)."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def perform_create(self, serializer):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        task = serializer.save(
            assigned_by=self.request.user,
            status='assigned',
            payment_status='not_assigned'
        )
        try:
            due_str = task.due_date.strftime('%b %d, %Y') if task.due_date else 'Flexible'
            send_html_email(
                f"New Task Assigned: {task.title}",
                task.assigned_to.email,
                task.assigned_to.first_name or task.assigned_to.username,
                type='task_assigned',
                task_title=task.title,
                task_description=task.description or '',
                due_date=due_str,
                assigned_by_name=f"{self.request.user.first_name} {self.request.user.last_name}".strip() or self.request.user.email
            )
        except Exception:
            pass


class ManagerTaskListView(generics.ListAPIView):
    """Manager sees all tasks."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        queryset = StaffTask.objects.all().order_by('-created_at')
        staff_id = self.request.query_params.get('staff_id')
        if staff_id:
            queryset = queryset.filter(assigned_to_id=staff_id)
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        return queryset


class ManagerTaskDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Manager views/updates/deletes a task."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_object(self):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        try:
            return StaffTask.objects.get(pk=self.kwargs['pk'])
        except StaffTask.DoesNotExist:
            raise NotFound()

    def perform_update(self, serializer):
        task = self.get_object()
        status = serializer.validated_data.get('status')
        if status == 'in_progress' and task.status == 'completed':
            if task.payment.filter(type='credit').exists():
                from rest_framework.exceptions import ValidationError
                raise ValidationError({'error': 'Cannot revert a paid task.'})
            serializer.validated_data['completed_at'] = None
        elif status == 'completed' and task.status != 'completed':
            serializer.validated_data['completed_at'] = timezone.now()
        serializer.save()


class ManagerCommentView(generics.ListCreateAPIView):
    """Manager views/adds comments on any task."""
    permission_classes = [IsAuthenticated]
    serializer_class = TaskCommentSerializer

    def get_queryset(self):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        return TaskComment.objects.filter(task_id=self.kwargs['pk']).order_by('created_at')

    def perform_create(self, serializer):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        task = StaffTask.objects.filter(pk=self.kwargs['pk']).first()
        if not task:
            raise NotFound()
        serializer.save(author=self.request.user, task=task)


class ManagerTaskReviewView(APIView):
    """Manager reviews submitted task: approve, request revision, or mark completed."""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not is_admin_or_manager(request.user):
            return Response({'error': 'Only managers and admins can review tasks.'}, status=403)
        try:
            task = StaffTask.objects.get(pk=pk)
        except StaffTask.DoesNotExist:
            return Response({'error': 'Task not found.'}, status=404)

        action = request.data.get('action') # 'approve', 'request_revision', 'complete'
        feedback = request.data.get('feedback', '').strip()

        if action == 'request_revision':
            if not feedback:
                return Response({'error': 'Feedback is required when requesting revisions.'}, status=400)
            task.status = 'revision_required'
            task.reviewer_feedback = feedback
            task.reviewed_by = request.user
            task.reviewed_at = timezone.now()
            task.revision_count += 1
            task.save()

            latest_hist = task.submission_history.first()
            if latest_hist:
                latest_hist.reviewer_feedback = feedback
                latest_hist.reviewed_by = request.user
                latest_hist.reviewed_at = timezone.now()
                latest_hist.save()

            try:
                send_html_email(
                    f"Revision Requested: {task.title}",
                    task.assigned_to.email,
                    task.assigned_to.first_name or task.assigned_to.username,
                    type='task_review_update',
                    task_title=task.title,
                    task_status='revision_required',
                    feedback=feedback
                )
            except Exception:
                pass

            return Response({'message': 'Task sent back for revision.', 'task': StaffTaskSerializer(task).data})

        elif action == 'approve':
            task.status = 'approved'
            task.reviewed_by = request.user
            task.reviewed_at = timezone.now()
            if feedback:
                task.reviewer_feedback = feedback
            task.save()

            try:
                send_html_email(
                    f"Task Deliverables Approved: {task.title}",
                    task.assigned_to.email,
                    task.assigned_to.first_name or task.assigned_to.username,
                    type='task_review_update',
                    task_title=task.title,
                    task_status='approved',
                    feedback=feedback or 'Great work! Your deliverables have been accepted.'
                )
            except Exception:
                pass

            return Response({'message': 'Task deliverables approved.', 'task': StaffTaskSerializer(task).data})

        elif action == 'complete':
            task.status = 'completed'
            task.completed_at = timezone.now()
            task.save()
            return Response({'message': 'Task marked as completed.', 'task': StaffTaskSerializer(task).data})

        return Response({'error': 'Invalid action. Choose approve, request_revision, or complete.'}, status=400)


class ManagerTaskPostpaidPaymentView(APIView):
    """Manager determines and approves postpaid payment amount after reviewing deliverables."""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not is_admin_or_manager(request.user):
            return Response({'error': 'Only managers and admins can set task payment.'}, status=403)
        try:
            task = StaffTask.objects.get(pk=pk)
        except StaffTask.DoesNotExist:
            return Response({'error': 'Task not found.'}, status=404)

        if task.assigned_to == request.user and not request.user.is_superuser:
            return Response({'error': 'Assignees cannot assign or approve their own payment.'}, status=403)

        action = request.data.get('action') # 'assign_amount' or 'approve_payment'
        amount_str = request.data.get('amount')
        notes = request.data.get('notes', '').strip()

        old_amount = task.payment_amount
        old_status = task.payment_status

        if action == 'assign_amount':
            try:
                amount = Decimal(str(amount_str))
                if amount < 0:
                    raise ValueError()
            except Exception:
                return Response({'error': 'Valid payment amount is required.'}, status=400)

            task.payment_amount = amount
            task.payment_status = 'amount_assigned'
            task.payment_assigned_by = request.user
            task.payment_assigned_at = timezone.now()
            if notes:
                task.payment_notes = notes
            task.save()

            TaskPaymentAuditLog.objects.create(
                task=task, changed_by=request.user,
                old_amount=old_amount, new_amount=amount,
                old_status=old_status, new_status='amount_assigned',
                reason=notes or 'Postpaid amount assigned by manager'
            )
            return Response({'message': f'Amount ₹{amount} assigned to task.', 'task': StaffTaskSerializer(task).data})

        elif action == 'approve_payment':
            if task.payment_amount <= 0:
                return Response({'error': 'Cannot approve payment of ₹0. Please assign an amount first.'}, status=400)

            task.payment_status = 'approved'
            task.payment_approved_by = request.user
            task.payment_approved_at = timezone.now()
            task.save()

            TaskPaymentAuditLog.objects.create(
                task=task, changed_by=request.user,
                old_amount=old_amount, new_amount=task.payment_amount,
                old_status=old_status, new_status='approved',
                reason=notes or 'Payment amount approved by manager'
            )
            return Response({'message': f'Payment of ₹{task.payment_amount} approved.', 'task': StaffTaskSerializer(task).data})

        return Response({'error': 'Invalid action. Choose assign_amount or approve_payment.'}, status=400)


class MarkTaskPaidView(APIView):
    """Manager marks a task as paid → creates credit transaction in staff wallet."""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not is_admin_or_manager(request.user):
            return Response({'error': 'Only managers/admins can mark tasks paid.'}, status=403)

        try:
            task = StaffTask.objects.get(pk=pk)
        except StaffTask.DoesNotExist:
            return Response({'error': 'Task not found.'}, status=404)

        if task.status != 'completed' and task.status != 'approved':
            return Response({'error': 'Task must be approved or completed before payment.'}, status=400)

        amount = Decimal(str(request.data.get('amount', task.payment_amount)))
        if amount <= 0:
            return Response({'error': 'Payment amount must be greater than 0.'}, status=400)

        # Get or create wallet for the assignee
        wallet, _ = StaffWallet.objects.get_or_create(staff=task.assigned_to)

        # Create credit transaction
        WalletTransaction.objects.create(
            wallet=wallet,
            task=task,
            type='credit',
            amount=amount,
            note=f'Payment for: {task.title}',
        )

        # Update wallet totals
        wallet.total_earned += amount
        wallet.save()

        # Update task
        task.payment_amount = amount
        task.payment_status = 'paid'
        task.paid_at = timezone.now()
        if task.status != 'completed':
            task.status = 'completed'
            task.completed_at = timezone.now()
        task.save()

        return Response({
            'message': f'₹{amount} credited to {task.assigned_to.email}',
            'wallet_balance': str(wallet.balance),
            'task': StaffTaskSerializer(task).data
        })


class SuperAdminOmniDashboardView(APIView):
    """Cross-platform command center for Super Admin giving complete visibility into all platforms."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_superuser:
            raise PermissionDenied('Only super admins can view the Omni Dashboard.')

        now = timezone.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # 1. Classes Platform Data
        classes_data = {
            'total_courses': Course.objects.count(),
            'active_courses': Course.objects.filter(is_active=True).count(),
            'total_teachers': User.objects.filter(role='teacher', platform='classes').count(),
            'approved_teachers': TeacherProfile.objects.filter(is_approved=True).count(),
            'total_students': User.objects.filter(role='student', platform='classes').count(),
            'total_bookings': Booking.objects.count(),
            'confirmed_bookings': Booking.objects.filter(booking_status='confirmed').count(),
            'total_revenue': float(Booking.objects.filter(payment_status__in=['advance_paid', 'fully_paid']).aggregate(total=db_models.Sum('advance_amount'))['total'] or 0),
            'sessions_month': ClassSession.objects.filter(scheduled_time__gte=month_start).count(),
            'live_or_needs_review': ClassSession.objects.filter(status__in=['Scheduled', 'Live', 'Needs Review']).count(),
        }

        # 2. GATE Platform Data
        gate_data = {
            'total_students': User.objects.filter(platform='gate', role='student').count(),
            'total_materials': StudyMaterial.objects.count(),
            'total_questions': Question.objects.count(),
            'total_tests_taken': MockTest.objects.count(),
            'pending_requests': CourseRequest.objects.filter(status='Pending').count(),
        }

        # 3. Staff & HR Operations Data
        staff_data = {
            'total_staff': User.objects.filter(role='staff').count(),
            'total_managers': User.objects.filter(role='manager').count(),
            'total_tasks': StaffTask.objects.count(),
            'tasks_in_review': StaffTask.objects.filter(status='submitted_for_review').count(),
            'tasks_completed': StaffTask.objects.filter(status='completed').count(),
            'payments_awaiting_approval': StaffTask.objects.filter(payment_status__in=['awaiting_review', 'amount_assigned']).count(),
            'total_payroll_earned': float(StaffWallet.objects.aggregate(total=db_models.Sum('total_earned'))['total'] or 0),
            'total_payroll_paid': float(StaffWallet.objects.aggregate(total=db_models.Sum('total_paid'))['total'] or 0),
        }

        # 4. Support & Inquiries Data
        support_data = {
            'pending_complaints': Complaint.objects.filter(status='Pending').count(),
            'resolved_complaints': Complaint.objects.filter(status='Resolved').count(),
            'pending_inquiries': ContactInquiry.objects.filter(status='Pending').count(),
            'resolved_inquiries': ContactInquiry.objects.filter(status='Resolved').count(),
        }

        # 5. Careers Data
        careers_data = {
            'total_applications': JobApplication.objects.count(),
            'pending_applications': JobApplication.objects.filter(status='pending').count(),
        }

        # 6. Global User Counts
        user_counts = {
            'total_users': User.objects.count(),
            'active_users': User.objects.filter(is_active=True).count(),
            'students': User.objects.filter(role='student').count(),
            'teachers': User.objects.filter(role='teacher').count(),
            'staff': User.objects.filter(role='staff').count(),
            'managers': User.objects.filter(role='manager').count(),
            'admins': User.objects.filter(role='admin').count(),
        }

        return Response({
            'classes': classes_data,
            'gate': gate_data,
            'staff': staff_data,
            'support': support_data,
            'careers': careers_data,
            'users': user_counts,
            'timestamp': now.isoformat()
        })


class ManagerWalletListView(generics.ListAPIView):
    """Manager sees all wallets."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffWalletSerializer

    def get_queryset(self):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        return StaffWallet.objects.select_related('staff').all().order_by('-updated_at')


class ManagerWalletDetailView(generics.RetrieveAPIView):
    """Manager views a specific wallet with transaction history."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffWalletSerializer

    def get_object(self):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        try:
            return StaffWallet.objects.get(pk=self.kwargs['pk'])
        except StaffWallet.DoesNotExist:
            raise NotFound()

class ManagerTransactionCreateView(generics.CreateAPIView):
    """Manager adds manual adjustment (credit/debit) to a wallet."""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        if not is_admin_or_manager(request.user):
            raise PermissionDenied()
        try:
            wallet = StaffWallet.objects.get(pk=pk)
        except StaffWallet.DoesNotExist:
            raise NotFound()
            
        t_type = request.data.get('type')
        amount = Decimal(str(request.data.get('amount', 0)))
        note = request.data.get('note', '')
        
        if t_type not in ['credit', 'debit'] or amount <= 0:
            return Response({'error': 'Invalid type or amount.'}, status=400)
            
        WalletTransaction.objects.create(
            wallet=wallet, type=t_type, amount=amount, note=note
        )
        
        if t_type == 'credit':
            wallet.total_earned += amount
        else:
            wallet.total_paid += amount
        wallet.save()
        
        return Response({'message': 'Transaction added successfully.'})

class ManagerDirectPayView(APIView):
    """Manager makes a direct payment/adjustment to any staff/teacher/mentor."""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        if not is_admin_or_manager(request.user):
            raise PermissionDenied()
            
        staff_id = request.data.get('staff_id')
        t_type = request.data.get('type')
        amount_str = request.data.get('amount', 0)
        note = request.data.get('note', '')
        
        try:
            amount = Decimal(str(amount_str))
        except:
            return Response({'error': 'Invalid amount.'}, status=400)
            
        if t_type not in ['credit', 'debit'] or amount <= 0:
            return Response({'error': 'Invalid type or amount.'}, status=400)
            
        try:
            staff_user = User.objects.get(pk=staff_id)
        except User.DoesNotExist:
            return Response({'error': 'Staff member not found.'}, status=404)
            
        wallet, _ = StaffWallet.objects.get_or_create(staff=staff_user)
        
        WalletTransaction.objects.create(
            wallet=wallet, type=t_type, amount=amount, note=note
        )
        
        if t_type == 'credit':
            wallet.total_earned += amount
        else:
            wallet.total_paid += amount
        wallet.save()
        
        return Response({
            'message': 'Direct transaction recorded successfully.',
            'wallet_balance': str(wallet.balance)
        })
