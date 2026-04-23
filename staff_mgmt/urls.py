from django.urls import path
from .views import (
    SuperAdminUserListView, SuperAdminUserCreateView, SuperAdminUserDetailView,
    AvailableModulesView, DepartmentListCreateView, DepartmentDetailView,
    StaffSignUpView, StaffProfileView, StaffMyModulesView,
    StaffTaskListView, StaffTaskUpdateView, TaskCommentView,
    StaffComplaintListView, StaffComplaintDetailView,
    StaffContactListView, StaffContactUpdateView,
    StaffJobApplicationListView, StaffJobApplicationUpdateView,
    AdminStaffListView, AdminStaffDetailView,
    AdminTaskCreateView, AdminTaskListView, AdminTaskDetailView,
)

urlpatterns = [
    # Super Admin: Cross-Platform User Management
    path('admin/users/', SuperAdminUserListView.as_view(), name='superadmin-user-list'),
    path('admin/users/create/', SuperAdminUserCreateView.as_view(), name='superadmin-user-create'),
    path('admin/users/<int:pk>/', SuperAdminUserDetailView.as_view(), name='superadmin-user-detail'),

    # Department Management
    path('admin/departments/', DepartmentListCreateView.as_view(), name='department-list-create'),
    path('admin/departments/<int:pk>/', DepartmentDetailView.as_view(), name='department-detail'),
    path('admin/departments/modules/', AvailableModulesView.as_view(), name='available-modules'),

    # Staff Self-Service
    path('staff/signup/', StaffSignUpView.as_view(), name='staff-signup'),
    path('staff/profile/', StaffProfileView.as_view(), name='staff-profile'),
    path('staff/modules/', StaffMyModulesView.as_view(), name='staff-my-modules'),
    path('staff/tasks/', StaffTaskListView.as_view(), name='staff-tasks'),
    path('staff/tasks/<int:pk>/update/', StaffTaskUpdateView.as_view(), name='staff-task-update'),
    path('staff/tasks/<int:pk>/comments/', TaskCommentView.as_view(), name='task-comments'),

    # Staff Module Access: Support
    path('staff/module/support/complaints/', StaffComplaintListView.as_view(), name='staff-complaints'),
    path('staff/module/support/complaints/<int:pk>/', StaffComplaintDetailView.as_view(), name='staff-complaint-detail'),
    path('staff/module/support/contacts/', StaffContactListView.as_view(), name='staff-contacts'),
    path('staff/module/support/contacts/<int:pk>/', StaffContactUpdateView.as_view(), name='staff-contact-update'),

    # Staff Module Access: Careers
    path('staff/module/careers/applications/', StaffJobApplicationListView.as_view(), name='staff-job-applications'),
    path('staff/module/careers/applications/<int:pk>/', StaffJobApplicationUpdateView.as_view(), name='staff-job-application-update'),

    # Admin Staff Management
    path('admin/staff/', AdminStaffListView.as_view(), name='admin-staff-list'),
    path('admin/staff/<int:pk>/', AdminStaffDetailView.as_view(), name='admin-staff-detail'),
    path('admin/staff/tasks/create/', AdminTaskCreateView.as_view(), name='admin-task-create'),
    path('admin/staff/tasks/', AdminTaskListView.as_view(), name='admin-task-list'),
    path('admin/staff/tasks/<int:pk>/', AdminTaskDetailView.as_view(), name='admin-task-detail'),
]
