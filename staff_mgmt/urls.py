from django.urls import path
from .views import (
    StaffSignUpView, StaffProfileView,
    StaffTaskListView, StaffTaskUpdateView, TaskCommentView,
    AdminStaffListView, AdminTaskCreateView, AdminTaskListView, AdminTaskDetailView,
)

urlpatterns = [
    # --- Staff Routes ---
    path('staff/signup/', StaffSignUpView.as_view(), name='staff-signup'),
    path('staff/profile/', StaffProfileView.as_view(), name='staff-profile'),
    path('staff/tasks/', StaffTaskListView.as_view(), name='staff-tasks'),
    path('staff/tasks/<int:pk>/update/', StaffTaskUpdateView.as_view(), name='staff-task-update'),
    path('staff/tasks/<int:pk>/comments/', TaskCommentView.as_view(), name='task-comments'),

    # --- Admin Staff Management Routes ---
    path('admin/staff/', AdminStaffListView.as_view(), name='admin-staff-list'),
    path('admin/staff/tasks/create/', AdminTaskCreateView.as_view(), name='admin-task-create'),
    path('admin/staff/tasks/', AdminTaskListView.as_view(), name='admin-task-list'),
    path('admin/staff/tasks/<int:pk>/', AdminTaskDetailView.as_view(), name='admin-task-detail'),
]
