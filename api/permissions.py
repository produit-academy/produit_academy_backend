# api/permissions.py
from rest_framework import permissions
from .models import CourseRequest

class IsBranchAdmin(permissions.BasePermission):
    """
    Allows access only to users with the 'branch_admin' role.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'branch_admin'

class IsApprovedStudent(permissions.BasePermission):
    """
    Allows access only to 'student' users with an 'Approved' course request.
    """
    def has_permission(self, request, view):
        if not (request.user.is_authenticated and request.user.role == 'student'):
            return False
        
        # Check if they have an approved request for their assigned branch
        return CourseRequest.objects.filter(
            student=request.user,
            branch=request.user.branch,
            status='Approved'
        ).exists()