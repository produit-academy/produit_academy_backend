from django.urls import path
from .views import (
    StudentComplaintView, AdminComplaintListView, AdminComplaintDetailView,
    ContactInquiryView, AdminContactListView, AdminContactUpdateView,
)

urlpatterns = [
    # --- Complaints ---
    path('student/complaints/', StudentComplaintView.as_view(), name='student-complaints'),
    path('admin/complaints/', AdminComplaintListView.as_view(), name='admin-complaints-list'),
    path('admin/complaints/<int:pk>/', AdminComplaintDetailView.as_view(), name='admin-complaints-detail'),

    # --- Contact Inquiries ---
    path('contact/', ContactInquiryView.as_view(), name='contact-inquiry'),
    path('admin/contacts/', AdminContactListView.as_view(), name='admin-contact-list'),
    path('admin/contacts/<int:pk>/', AdminContactUpdateView.as_view(), name='admin-contact-update'),
]
