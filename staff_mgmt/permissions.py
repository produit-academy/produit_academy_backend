from rest_framework.permissions import BasePermission


class HasModuleAccess(BasePermission):
    """
    Checks if a staff member's department grants access to a specific module.
    Set module_key on the view. Admins always have access.
    """
    def has_permission(self, request, view):
        user = request.user
        if user.is_superuser or user.is_staff or user.role == 'admin':
            return True
        if user.role != 'staff':
            return False
        module_key = getattr(view, 'module_key', None)
        if not module_key:
            return False
        try:
            return user.staff_profile.has_module_access(module_key)
        except Exception:
            return False
