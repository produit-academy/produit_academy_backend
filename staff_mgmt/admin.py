from django.contrib import admin
from .models import StaffProfile, StaffTask, TaskComment


@admin.register(StaffProfile)
class StaffProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'designation', 'joined_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name')


@admin.register(StaffTask)
class StaffTaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'assigned_to', 'assigned_by', 'status', 'due_date', 'created_at')
    list_filter = ('status', 'due_date')
    search_fields = ('title', 'assigned_to__email')


@admin.register(TaskComment)
class TaskCommentAdmin(admin.ModelAdmin):
    list_display = ('task', 'author', 'created_at')
    search_fields = ('text', 'author__email')
