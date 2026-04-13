from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.models import User, StaffProfile, StaffTask, TaskComment
from .serializers import StaffProfileSerializer, StaffTaskSerializer, TaskCommentSerializer


# --- STAFF VIEWS ---

class StaffSignUpView(generics.CreateAPIView):
    """Admin creates a staff account"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can create staff accounts'}, status=403)

        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        phone_number = request.data.get('phone_number', '')
        designation = request.data.get('designation', '')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=400)

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            role='staff',
            is_verified=True
        )

        profile = StaffProfile.objects.create(
            user=user,
            designation=designation
        )

        return Response({
            'message': 'Staff account created successfully',
            'user_id': user.id,
            'email': user.email
        }, status=201)


class StaffProfileView(generics.RetrieveUpdateAPIView):
    """Staff can view and update their own profile"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffProfileSerializer

    def get_object(self):
        if self.request.user.role != 'staff':
            raise PermissionDenied('Only staff members can access this.')
        profile, created = StaffProfile.objects.get_or_create(user=self.request.user)
        return profile

    def patch(self, request, *args, **kwargs):
        profile = self.get_object()
        serializer = StaffProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class StaffTaskListView(generics.ListAPIView):
    """Staff sees only their assigned tasks"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        if self.request.user.role != 'staff':
            raise PermissionDenied('Only staff members can access this.')
        return StaffTask.objects.filter(assigned_to=self.request.user).order_by('-created_at')


class StaffTaskUpdateView(generics.UpdateAPIView):
    """Staff can mark task complete and add remarks"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_object(self):
        if self.request.user.role != 'staff':
            raise PermissionDenied('Only staff members can access this.')
        try:
            return StaffTask.objects.get(pk=self.kwargs['pk'], assigned_to=self.request.user)
        except StaffTask.DoesNotExist:
            raise NotFound('Task not found.')

    def patch(self, request, *args, **kwargs):
        task = self.get_object()
        allowed_fields = ['status', 'remarks']
        data = {k: v for k, v in request.data.items() if k in allowed_fields}

        if data.get('status') == 'completed' and task.status != 'completed':
            from django.utils import timezone
            data['completed_at'] = timezone.now()

        serializer = StaffTaskSerializer(task, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class TaskCommentView(generics.ListCreateAPIView):
    """Staff and admin can view and add comments on a task"""
    permission_classes = [IsAuthenticated]
    serializer_class = TaskCommentSerializer

    def get_queryset(self):
        task_id = self.kwargs['pk']
        user = self.request.user
        if user.role == 'staff':
            # staff can only comment on their own tasks
            task = StaffTask.objects.filter(pk=task_id, assigned_to=user).first()
            if not task:
                raise PermissionDenied('Task not found or not assigned to you.')
        elif user.role != 'admin':
            raise PermissionDenied('Access denied.')
        return TaskComment.objects.filter(task_id=task_id).order_by('created_at')

    def perform_create(self, serializer):
        task_id = self.kwargs['pk']
        user = self.request.user
        if user.role == 'staff':
            task = StaffTask.objects.filter(pk=task_id, assigned_to=user).first()
            if not task:
                raise PermissionDenied('Task not found or not assigned to you.')
        elif user.role == 'admin':
            task = StaffTask.objects.filter(pk=task_id).first()
            if not task:
                raise NotFound('Task not found.')
        else:
            raise PermissionDenied('Access denied.')
        serializer.save(author=user, task=task)


# --- ADMIN STAFF MANAGEMENT VIEWS ---

class AdminStaffListView(generics.ListAPIView):
    """Admin can see all staff members"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffProfileSerializer

    def get_queryset(self):
        if self.request.user.role != 'admin':
            raise PermissionDenied('Only admins can access this.')
        return StaffProfile.objects.select_related('user').all()


class AdminTaskCreateView(generics.CreateAPIView):
    """Admin assigns a task to a staff member"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def perform_create(self, serializer):
        if self.request.user.role != 'admin':
            raise PermissionDenied('Only admins can assign tasks.')
        serializer.save(assigned_by=self.request.user)


class AdminTaskListView(generics.ListAPIView):
    """Admin can see all tasks or filter by staff"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_queryset(self):
        if self.request.user.role != 'admin':
            raise PermissionDenied('Only admins can access this.')
        staff_id = self.request.query_params.get('staff_id')
        if staff_id:
            return StaffTask.objects.filter(assigned_to_id=staff_id).order_by('-created_at')
        return StaffTask.objects.all().order_by('-created_at')


class AdminTaskDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin can view, edit or delete any task"""
    permission_classes = [IsAuthenticated]
    serializer_class = StaffTaskSerializer

    def get_object(self):
        if self.request.user.role != 'admin':
            raise PermissionDenied('Only admins can access this.')
        try:
            return StaffTask.objects.get(pk=self.kwargs['pk'])
        except StaffTask.DoesNotExist:
            raise NotFound('Task not found.')
