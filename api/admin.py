from django.contrib import admin
from .models import User, Branch, Session


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'platform', 'branch', 'is_verified')
    list_filter = ('role', 'platform', 'branch', 'is_verified')
    search_fields = ('username', 'email', 'student_id')

@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at')