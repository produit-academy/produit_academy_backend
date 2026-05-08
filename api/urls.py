from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register(r'admin/questions', AdminQuestionBankView, basename='admin-questions')

urlpatterns = [
    # --- Auth & Core ---
    path('', include(router.urls)),
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

    # --- Student Custom Mock Tests ---
    path('student/tests/generate/', GenerateMockTestView.as_view(), name='generate-test'),
    path('student/tests/<int:pk>/submit/', SubmitMockTestView.as_view(), name='submit-test'),
    path('student/tests/history/', StudentMockTestHistoryView.as_view(), name='test-history'),
    path('student/tests/<int:pk>/analytics/', StudentMockTestAnalyticsView.as_view(), name='test-analytics'),
    path('student/tests/<int:pk>/questions/', StudentMockTestQuestionsView.as_view(), name='test-questions-list'),

    # --- Admin User Management ---
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('admin/students/', StudentListView.as_view(), name='student-list'),
    path('admin/students/<int:pk>/', StudentManageView.as_view(), name='student-manage'),
    path('admin/students/<int:pk>/history/', AdminStudentHistoryView.as_view(), name='admin-student-history'),
    path('courserequests/<int:pk>/update/', CourseRequestUpdateView.as_view(), name='course-request-update'),
    path('student/complaints/', StudentComplaintView.as_view(), name='student-complaints'),
    path('admin/complaints/', AdminComplaintListView.as_view(), name='admin-complaints-list'),
    path('admin/complaints/<int:pk>/', AdminComplaintDetailView.as_view(), name='admin-complaints-detail'),
    path('contact/', ContactInquiryView.as_view(), name='contact-inquiry'),
    path('admin/contacts/', AdminContactListView.as_view(), name='admin-contact-list'),
    path('admin/contacts/<int:pk>/', AdminContactUpdateView.as_view(), name='admin-contact-update'),

    # --- Staff Routes ---
    path('staff/signup/', StaffSignUpView.as_view(), name='staff-signup'),
    path('staff/profile/', StaffProfileView.as_view(), name='staff-profile'),
    path('staff/tasks/', StaffTaskListView.as_view(), name='staff-tasks'),
    path('staff/tasks/<int:pk>/update/', StaffTaskUpdateView.as_view(), name='staff-task-update'),
    path('staff/tasks/<int:pk>/comments/', TaskCommentView.as_view(), name='task-comments'),
    path('staff/wallet/', StaffWalletView.as_view(), name='staff-wallet'),

    # --- Admin Staff Management Routes ---
    path('admin/staff/', AdminStaffListView.as_view(), name='admin-staff-list'),
    path('admin/staff/tasks/create/', AdminTaskCreateView.as_view(), name='admin-task-create'),
    path('admin/staff/tasks/', AdminTaskListView.as_view(), name='admin-task-list'),
    path('admin/staff/tasks/<int:pk>/', AdminTaskDetailView.as_view(), name='admin-task-detail'),

    # --- Manager Routes ---
    path('manager/signup/', ManagerSignUpView.as_view(), name='manager-signup'),
    path('manager/staff/', ManagerStaffListView.as_view(), name='manager-staff-list'),
    path('manager/tasks/create/', ManagerTaskCreateView.as_view(), name='manager-task-create'),
    path('manager/tasks/', ManagerTaskListView.as_view(), name='manager-task-list'),
    path('manager/tasks/<int:pk>/', ManagerTaskDetailView.as_view(), name='manager-task-detail'),
    path('manager/tasks/<int:pk>/comments/', ManagerCommentView.as_view(), name='manager-task-comments'),
    path('manager/tasks/<int:pk>/pay/', MarkTaskPaidView.as_view(), name='mark-task-paid'),
    path('manager/wallets/', ManagerWalletListView.as_view(), name='manager-wallet-list'),
    path('manager/wallets/<int:pk>/', ManagerWalletDetailView.as_view(), name='manager-wallet-detail'),
    path('manager/wallets/<int:pk>/debit/', DebitWalletView.as_view(), name='debit-wallet'),
]