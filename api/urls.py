from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('branches/', BranchListView.as_view(), name='branch-list'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('student/dashboard/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('materials/', StudyMaterialView.as_view(), name='materials-list'),
    path('materials/upload/', StudyMaterialUploadView.as_view(), name='material-upload'),
    path('courserequest/', CourseRequestView.as_view(), name='course-request-detail'),
    path('courserequests/<int:pk>/update/', CourseRequestUpdateView.as_view(), name='course-request-update'),
    path('admin/students/', StudentListView.as_view(), name='student-list'),
    path('admin/students/<int:pk>/', StudentManageView.as_view(), name='student-manage'),
    path('profile/', ProfileView.as_view(), name='user-profile'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset-otp/', PasswordResetRequestOTPView.as_view(), name='password-reset-otp'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('materials/<int:pk>/view/', MaterialFileView.as_view(), name='material-view'),
    path('student/quizzes/<int:pk>/', StudentQuizDetailView.as_view(), name='quiz-detail'),
    path('student/quizzes/<int:pk>/submit/', QuizSubmitView.as_view(), name='quiz-submit'),
    path('admin/quizzes/create/', QuizCreateView.as_view(), name='quiz-create'),
    path('student/analytics/', StudentAnalyticsListView.as_view(), name='student-analytics'),
    path('student/analytics/<int:pk>/', StudentResultDetailView.as_view(), name='student-result-detail'),
]