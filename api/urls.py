from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

# --- Import all the new mock test views ---
from .views import (
    QuizListCreateView, QuestionCreateView, StudentQuizListView,
    StudentQuizDetailView, SubmitQuizView, StudentAnalyticsView
)

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

    # --- NEW MOCK TEST URLS ---
    
    # Branch Admin URLs
    path('branch-admin/quizzes/', QuizListCreateView.as_view(), name='quiz-list-create'),
    path('branch-admin/quizzes/<int:quiz_id>/questions/', QuestionCreateView.as_view(), name='question-create'),
    
    # Student URLs
    path('student/quizzes/', StudentQuizListView.as_view(), name='student-quiz-list'),
    path('student/quizzes/<int:pk>/', StudentQuizDetailView.as_view(), name='student-quiz-detail'),
    path('student/quizzes/<int:quiz_id>/submit/', SubmitQuizView.as_view(), name='student-quiz-submit'),
    path('student/analytics/', StudentAnalyticsView.as_view(), name='student-analytics'),
]