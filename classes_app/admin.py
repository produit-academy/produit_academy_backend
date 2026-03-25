from django.contrib import admin
from .models import Course, Enrollment, ClassSession, AttendanceRecord


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ('name', 'mentor', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    filter_horizontal = ('teachers',)


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
