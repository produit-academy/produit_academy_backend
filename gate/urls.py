from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CourseRequestView, CourseRequestUpdateView,
    StudyMaterialView, StudyMaterialUploadView, MaterialFileView,
    AdminQuestionBankView,
    GenerateMockTestView, SubmitMockTestView,
    StudentMockTestHistoryView, AdminStudentHistoryView,
    StudentMockTestAnalyticsView, StudentMockTestQuestionsView,
)

router = DefaultRouter()
router.register(r'admin/questions', AdminQuestionBankView, basename='admin-questions')

urlpatterns = [
    # --- Router ---
    path('', include(router.urls)),

    # --- Course Requests & Materials ---
    path('courserequest/', CourseRequestView.as_view(), name='course-request-detail'),
    path('courserequests/<int:pk>/update/', CourseRequestUpdateView.as_view(), name='course-request-update'),
    path('materials/', StudyMaterialView.as_view(), name='materials-list'),
    path('materials/upload/', StudyMaterialUploadView.as_view(), name='material-upload'),
    path('materials/<int:pk>/view/', MaterialFileView.as_view(), name='material-view'),

    # --- Student Custom Mock Tests ---
    path('student/tests/generate/', GenerateMockTestView.as_view(), name='generate-test'),
    path('student/tests/<int:pk>/submit/', SubmitMockTestView.as_view(), name='submit-test'),
    path('student/tests/history/', StudentMockTestHistoryView.as_view(), name='test-history'),
    path('student/tests/<int:pk>/analytics/', StudentMockTestAnalyticsView.as_view(), name='test-analytics'),
    path('student/tests/<int:pk>/questions/', StudentMockTestQuestionsView.as_view(), name='test-questions-list'),

    # --- Admin Student History ---
    path('admin/students/<int:pk>/history/', AdminStudentHistoryView.as_view(), name='admin-student-history'),
]
