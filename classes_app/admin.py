from django.contrib import admin
from .models import (
    Course, Subject, Enrollment, ClassSession, AttendanceRecord,
    TeacherProfile, TeacherDemoVideo, Booking, BookingSchedule, EmailLog,
)


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('name',)


@admin.register(Subject)
class SubjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'course', 'is_active', 'created_at')
    list_filter = ('course', 'is_active')
    search_fields = ('name', 'course__name')


@admin.register(TeacherProfile)
class TeacherProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_approved', 'hourly_rate', 'google_meet_link')
    list_filter = ('is_approved',)
    search_fields = ('user__email', 'user__first_name', 'user__last_name')


@admin.register(Enrollment)
class EnrollmentAdmin(admin.ModelAdmin):
    list_display = ('student', 'course', 'enrolled_at')
    list_filter = ('course',)
    search_fields = ('student__username', 'student__email')


@admin.register(ClassSession)
class ClassSessionAdmin(admin.ModelAdmin):
    list_display = ('title', 'course', 'teacher', 'scheduled_time', 'status')
    list_filter = ('status', 'course')
    search_fields = ('title',)


@admin.register(AttendanceRecord)
class AttendanceRecordAdmin(admin.ModelAdmin):
    list_display = ('class_session', 'student', 'status', 'marked_by', 'timestamp')
    list_filter = ('status', 'class_session__course')
    search_fields = ('student__username',)


@admin.register(TeacherDemoVideo)
class TeacherDemoVideoAdmin(admin.ModelAdmin):
    list_display = ('title', 'teacher', 'video_type', 'order', 'created_at')
    list_filter = ('video_type',)
    search_fields = ('title', 'teacher__email')


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ('student', 'teacher', 'subject', 'booking_status', 'payment_status', 'total_amount', 'created_at')
    list_filter = ('booking_status', 'payment_status')
    search_fields = ('student__email', 'teacher__email', 'subject__name')


@admin.register(BookingSchedule)
class BookingScheduleAdmin(admin.ModelAdmin):
    list_display = ('booking', 'date', 'start_time', 'end_time', 'status')
    list_filter = ('status',)


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    list_display = ('recipient_email', 'email_type', 'subject', 'status', 'created_at')
    list_filter = ('email_type', 'status')
    search_fields = ('recipient_email', 'subject')
