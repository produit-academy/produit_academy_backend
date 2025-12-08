from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

# Router for Admin ViewSets
router = DefaultRouter()

router.register(r'admin/questions', AdminQuestionBankView, basename='admin-questions')

urlpatterns = [
    # --- Auth & Core ---
    path('', include(router.urls)), # Includes admin/categories and admin/questions
    path('branches/', BranchListView.as_view(), name='branch-list'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset-otp/', PasswordResetRequestOTPView.as_view(), name='password-reset-otp'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('profile/', ProfileView.as_view(), name='user-profile'),

    # --- Student Dashboard & Materials ---
    path('student/dashboard/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('courserequest/', CourseRequestView.as_view(), name='course-request-detail'),
    path('materials/', StudyMaterialView.as_view(), name='materials-list'),
    path('materials/upload/', StudyMaterialUploadView.as_view(), name='material-upload'),
    path('materials/<int:pk>/view/', MaterialFileView.as_view(), name='material-view'),

    # --- NEW: Student Custom Mock Tests ---
    path('student/tests/generate/', GenerateMockTestView.as_view(), name='generate-test'),
    path('student/tests/<int:pk>/submit/', SubmitMockTestView.as_view(), name='submit-test'),
    path('student/tests/history/', StudentMockTestHistoryView.as_view(), name='test-history'),
    path('student/tests/<int:pk>/analytics/', StudentMockTestAnalyticsView.as_view(), name='test-analytics'),

    # --- Admin User Management ---
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('admin/students/', StudentListView.as_view(), name='student-list'),
    path('admin/students/<int:pk>/', StudentManageView.as_view(), name='student-manage'),
    path('admin/students/<int:pk>/history/', AdminStudentHistoryView.as_view(), name='admin-student-history'),
    path('courserequests/<int:pk>/update/', CourseRequestUpdateView.as_view(), name='course-request-update'),
]