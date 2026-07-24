from django.urls import path
from .views import (
    ClassesMeView,
    StudentDashboardView,
    TeacherDashboardView,
    SessionCreateView,
    SessionRosterView,
    BulkAttendanceView,
    PublicCourseListView,
    AdminCourseListCreateView,
    AdminCourseDetailView,
    AdminBulkEnrollView,
    AdminStatsView,
    AdminEnrollmentListView,
    StudentStatsView,
    AdminStaffManagementView,
    AdminAssignStaffView,
    AdminStaffDetailView,
    AdminStudentDetailView,
    AdminEnrollmentToggleCompletionView,
    AdminUserAnalyticsView,
    ScheduleDemoView, TeacherDemoLinkView, AcceptDemoView, RejectDemoView,
    BookSessionView, CompleteSessionView,
    ClassesProfileView, ClassesChangePasswordView,
    TeacherAvailabilityView, StudentTeacherSlotsView, CancelSessionView,
)
from .views_booking import (
    SubjectListView,
    TeachersBySubjectView,
    TeacherProfileDetailView,
    StudentBookTeacherView,
    DummyPaymentView,
    StudentBookingsListView,
    StudentPaymentHistoryView,
    TeacherProfileManageView,
    TeacherDemoVideoManageView,
    TeacherBookingsView,
    CancelScheduleView,
    AdminStudentsListView,
    AdminBookingsListView,
    AdminSubjectManageView,
)

urlpatterns = [
    # Auth & Config
    path('me/', ClassesMeView.as_view(), name='classes-me'),
    path('profile/', ClassesProfileView.as_view(), name='classes-profile'),
    path('change-password/', ClassesChangePasswordView.as_view(), name='classes-change-password'),

    # Public Data
    path('courses/', PublicCourseListView.as_view(), name='classes-public-courses'),
    path('subjects/', SubjectListView.as_view(), name='classes-subjects'),
    path('teachers/', TeachersBySubjectView.as_view(), name='classes-teachers-by-subject'),
    path('teacher-profile/<int:pk>/', TeacherProfileDetailView.as_view(), name='classes-teacher-profile'),

    # Dashboard Feeds
    path('student/dashboard/', StudentDashboardView.as_view(), name='classes-student-dashboard'),
    path('teacher/dashboard/', TeacherDashboardView.as_view(), name='classes-teacher-dashboard'),
    path('student/stats/', StudentStatsView.as_view(), name='student-stats'),

    # Operations
    path('sessions/create/', SessionCreateView.as_view(), name='classes-session-create'),
    path('sessions/<int:pk>/roster/', SessionRosterView.as_view(), name='classes-session-roster'),
    path('sessions/<int:pk>/attendance/', BulkAttendanceView.as_view(), name='classes-session-attendance'),

    # 1-to-1 Demo & Flexible Booking
    path('schedule-demo/', ScheduleDemoView.as_view(), name='admin-schedule-demo'),
    path('teacher/demo/<int:pk>/link/', TeacherDemoLinkView.as_view(), name='teacher-demo-link'),
    path('student/demo/<int:pk>/accept/', AcceptDemoView.as_view(), name='student-accept-demo'),
    path('student/demo/<int:pk>/reject/', RejectDemoView.as_view(), name='student-reject-demo'),
    path('student/book-session/', BookSessionView.as_view(), name='student-book-session'),
    path('teacher/session/<int:pk>/complete/', CompleteSessionView.as_view(), name='teacher-complete-session'),

    # Student Booking & Payment
    path('student/book-teacher/', StudentBookTeacherView.as_view(), name='student-book-teacher'),
    path('student/pay/', DummyPaymentView.as_view(), name='student-dummy-payment'),
    path('student/bookings/', StudentBookingsListView.as_view(), name='student-bookings'),
    path('student/payments/', StudentPaymentHistoryView.as_view(), name='student-payments'),

    # Teacher Availability, Profile & Bookings
    path('teacher/availability/', TeacherAvailabilityView.as_view(), name='teacher-availability'),
    path('teacher/manage-profile/', TeacherProfileManageView.as_view(), name='teacher-manage-profile'),
    path('teacher/demo-videos/', TeacherDemoVideoManageView.as_view(), name='teacher-demo-videos'),
    path('teacher/bookings/', TeacherBookingsView.as_view(), name='teacher-bookings'),
    path('schedule/<int:pk>/cancel/', CancelScheduleView.as_view(), name='schedule-cancel'),
    path('student/teacher-slots/', StudentTeacherSlotsView.as_view(), name='student-teacher-slots'),
    path('session/<int:pk>/cancel/', CancelSessionView.as_view(), name='session-cancel'),

    # Admin
    path('admin/staff/', AdminStaffManagementView.as_view(), name='admin-staff-management'),
    path('admin/staff/<int:pk>/', AdminStaffDetailView.as_view(), name='admin-staff-detail'),
    path('admin/students/', AdminStudentsListView.as_view(), name='admin-students-list'),
    path('admin/students/<int:pk>/', AdminStudentDetailView.as_view(), name='admin-student-detail'),
    path('admin/enrollments/<int:pk>/toggle-completion/', AdminEnrollmentToggleCompletionView.as_view(), name='admin-enrollment-toggle-completion'),
    path('admin/assign-staff/', AdminAssignStaffView.as_view(), name='admin-assign-staff'),
    path('admin/courses/', AdminCourseListCreateView.as_view(), name='classes-admin-courses'),
    path('admin/courses/<int:pk>/', AdminCourseDetailView.as_view(), name='classes-admin-course-detail'),
    path('admin/enrollments/', AdminBulkEnrollView.as_view(), name='classes-admin-enroll'),
    path('admin/enrollments/list/', AdminEnrollmentListView.as_view(), name='classes-admin-enrollment-list'),
    path('admin/stats/', AdminStatsView.as_view(), name='classes-admin-stats'),
    path('admin/analytics/user/<int:pk>/', AdminUserAnalyticsView.as_view(), name='admin-user-analytics'),
    path('admin/bookings/', AdminBookingsListView.as_view(), name='admin-bookings-list'),
    path('admin/subjects/', AdminSubjectManageView.as_view(), name='admin-subjects'),
]
