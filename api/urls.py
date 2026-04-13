from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    MyTokenObtainPairView, SignUpView, VerifyOTPView, ResendOTPView,
    PasswordResetRequestOTPView, PasswordResetConfirmView,
    ProfileView, BranchListView,
    StudentDashboardView, AdminDashboardView,
    StudentListView, StudentManageView,
)

urlpatterns = [
    # --- Auth & Core ---
    path('branches/', BranchListView.as_view(), name='branch-list'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset-otp/', PasswordResetRequestOTPView.as_view(), name='password-reset-otp'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('profile/', ProfileView.as_view(), name='user-profile'),

    # --- Dashboards & Student Management ---
    path('student/dashboard/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('admin/students/', StudentListView.as_view(), name='student-list'),
    path('admin/students/<int:pk>/', StudentManageView.as_view(), name='student-manage'),
]
