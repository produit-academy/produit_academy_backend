from django.urls import path
from .views import JobApplicationCreateView, AdminJobApplicationListView, AdminJobApplicationDetailView

urlpatterns = [
    path('apply/', JobApplicationCreateView.as_view(), name='career-apply'),
    path('admin/list/', AdminJobApplicationListView.as_view(), name='admin-career-list'),
    path('admin/<int:pk>/', AdminJobApplicationDetailView.as_view(), name='admin-career-detail'), # Added this line
]