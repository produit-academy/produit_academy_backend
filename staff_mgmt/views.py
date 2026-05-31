from django.db import models as db_models
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.models import User, Branch, Department, StaffProfile, StaffTask, TaskComment, Complaint, ContactInquiry, StaffWallet, WalletTransaction
from classes_app.models import Course, TeacherProfile
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

        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'A user with this email already exists.'}, status=400)

        valid_types = ['platform_admin', 'support_staff', 'contact_staff', 'hr_staff', 'manager', 'custom_staff']
        if account_type not in valid_types:
            return Response({'error': 'Invalid account type.'}, status=400)

        if account_type == 'platform_admin':
            # Create a platform admin
            platform = request.data.get('platform', 'gate')
            user = User.objects.create_user(
                username=email, email=email, password=password,
                first_name=first_name, last_name=last_name,
                phone_number=phone_number, role='admin', platform=platform,
                is_verified=True, is_staff=True,
            )
            return Response({
                'message': f'{platform.upper()} admin account created.',
                'user_id': user.id, 'email': user.email,
            }, status=201)

        if account_type == 'manager':
            user = User.objects.create_user(
                username=email, email=email, password=password,
                first_name=first_name, last_name=last_name,
                phone_number=phone_number, role='manager', is_verified=True,
            )
            StaffProfile.objects.create(user=user, designation='Manager')
            return Response({
                'message': 'Manager account created.',
                'user_id': user.id, 'email': user.email,
            }, status=201)

        # Staff accounts
        user = User.objects.create_user(
            username=email, email=email, password=password,
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

        return Response({
            'message': f'{label} account created.',
            'user_id': user.id, 'email': user.email,
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
            platform='classes', role__in=['teacher', 'mentor']
        ).order_by('-date_joined')

        # Prefetch teacher profiles with subjects to avoid N+1
        teacher_profiles = {}
        for tp in TeacherProfile.objects.filter(
            user__in=staff
        ).prefetch_related('subjects').select_related('user'):
            teacher_profiles[tp.user_id] = list(tp.subjects.values('id', 'name'))

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
            'subjects': teacher_profiles.get(u.id, []),
        } for u in staff]

        return Response(data)

    def post(self, request):
        if not (is_admin(request.user) or request.user.role == 'staff'):
            return Response({'error': 'Only HR and admins can onboard staff.'}, status=403)

        email = request.data.get('email')
        role = request.data.get('role') # 'teacher' or 'mentor'
        subjects = request.data.get('subjects', []) # list of course IDs
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        phone_number = request.data.get('phone_number', '')

        if not email or role not in ['teacher', 'mentor']:
            return Response({'error': 'Valid email and role (teacher/mentor) required.'}, status=400)
            
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
            profile = TeacherProfile.objects.create(user=user)
            if subjects:
                profile.subjects.set(Course.objects.filter(id__in=subjects))
                
        try:
            send_html_email(
                'Welcome to Produit Academy Classes',
                user.email,
                f"{first_name} {last_name}".strip() or user.email.split('@')[0],
                otp,
                type='staff_otp',
                from_email=HR_FROM_EMAIL,
            )
        except Exception:
            pass
            
        return Response({'message': f'{role.capitalize()} onboarded successfully.', 'user_id': user.id}, status=201)


class OnboardStaffDetailView(APIView):
    """Edit or delete an onboarded teacher/mentor."""
    permission_classes = [IsAuthenticated]

    def get_staff_user(self, pk):
        try:
            return User.objects.get(pk=pk, platform='classes', role__in=['teacher', 'mentor'])
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
            profile.subjects.set(Course.objects.filter(id__in=request.data['subjects']))

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
            user = User.objects.get(id=user_id, role__in=['teacher', 'mentor'])
            if user.is_verified:
                return Response({'message': 'User already verified.'}, status=400)

            # Generate random password
            raw_password = 'PA-' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            user.set_password(raw_password)
            user.is_verified = True
            user.save()
            
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
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_object(self):
        user = self.request.user
        if user.role not in ['staff', 'manager']:
            raise PermissionDenied()
        try:
            return StaffTask.objects.get(pk=self.kwargs['pk'], assigned_to=user)
        except StaffTask.DoesNotExist:
            raise NotFound()

    def patch(self, request, *args, **kwargs):
        task = self.get_object()
        data = {k: v for k, v in request.data.items() if k in ['status', 'remarks']}
        if data.get('status') == 'completed' and task.status != 'completed':
            data['completed_at'] = timezone.now()
        elif data.get('status') == 'in_progress' and task.status == 'completed':
            if task.payment.filter(type='credit').exists():
                return Response({'error': 'Cannot revert a paid task.'}, status=400)
            data['completed_at'] = None

        serializer = StaffTaskSerializer(task, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


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


class StaffJobApplicationUpdateView(generics.UpdateAPIView):
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
        serializer.save(assigned_by=self.request.user)


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
        if request.user.role not in ['staff', 'manager', 'teacher', 'mentor']:
            raise PermissionDenied('Only staff/teachers/mentors can view their wallet.')
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
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        queryset = User.objects.filter(
            role__in=['staff', 'manager', 'teacher', 'mentor']
        ).order_by('-date_joined')
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
    """Manager creates and assigns tasks."""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def perform_create(self, serializer):
        if not is_admin_or_manager(self.request.user):
            raise PermissionDenied()
        serializer.save(assigned_by=self.request.user)


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


class MarkTaskPaidView(APIView):
    """Manager marks a task as paid → creates wallet transaction."""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not is_admin_or_manager(request.user):
            return Response({'error': 'Only managers/admins can mark tasks paid.'}, status=403)

        try:
            task = StaffTask.objects.get(pk=pk)
        except StaffTask.DoesNotExist:
            return Response({'error': 'Task not found.'}, status=404)

        if task.status != 'completed':
            return Response({'error': 'Task must be completed before payment.'}, status=400)

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

        # Update task payment amount if different
        task.payment_amount = amount
        task.save()

        return Response({
            'message': f'₹{amount} credited to {task.assigned_to.email}',
            'wallet_balance': str(wallet.balance),
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
