from django.contrib import admin
from .models import Complaint, ContactInquiry


@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ('subject', 'student', 'status', 'created_at', 'resolved_at')
    list_filter = ('status', 'created_at')
    search_fields = ('subject', 'student__email', 'student__username')


@admin.register(ContactInquiry)
class ContactInquiryAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'platform', 'course', 'status', 'created_at')
    list_filter = ('platform', 'status', 'course', 'created_at')
    search_fields = ('name', 'email', 'message')
