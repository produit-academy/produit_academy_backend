from django.urls import path
from .views import (
    ClassesMeView,
    StudentDashboardView,
    TeacherDashboardView,
    SessionCreateView,
    SessionRosterView,
    BulkAttendanceView,
    MentorDashboardView,
    PublicCourseListView,
    AdminCourseListCreateView,
    AdminCourseDetailView,
    AdminBulkEnrollView,
    AdminStatsView,
    AdminEnrollmentListView,
)

urlpatterns = [
    # Auth & Config
    path('me/', ClassesMeView.as_view(), name='classes-me'),

    # Public Data
    path('courses/', PublicCourseListView.as_view(), name='classes-public-courses'),

    # Dashboard Feeds
    path('student/dashboard/', StudentDashboardView.as_view(), name='classes-student-dashboard'),
    path('teacher/dashboard/', TeacherDashboardView.as_view(), name='classes-teacher-dashboard'),
    path('mentor/dashboard/', MentorDashboardView.as_view(), name='classes-mentor-dashboard'),

    # Operations
    path('sessions/create/', SessionCreateView.as_view(), name='classes-session-create'),
    path('sessions/<int:pk>/roster/', SessionRosterView.as_view(), name='classes-session-roster'),
    path('sessions/<int:pk>/attendance/', BulkAttendanceView.as_view(), name='classes-session-attendance'),

    # Admin
    path('admin/courses/', AdminCourseListCreateView.as_view(), name='classes-admin-courses'),
    path('admin/courses/<int:pk>/', AdminCourseDetailView.as_view(), name='classes-admin-course-detail'),
    path('admin/enrollments/', AdminBulkEnrollView.as_view(), name='classes-admin-enroll'),
    path('admin/enrollments/list/', AdminEnrollmentListView.as_view(), name='classes-admin-enrollment-list'),
    path('admin/stats/', AdminStatsView.as_view(), name='classes-admin-stats'),
]
