from django.contrib import admin
from .models import (
    User, Branch, StudyMaterial, CourseRequest, Session,
    Question, Choice, MockTest, MockTestQuestion
)

# --- INLINES ---

class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 4

class MockTestQuestionInline(admin.TabularInline):
    model = MockTestQuestion
    readonly_fields = ('question', 'selected_choice', 'is_correct', 'order')
    extra = 0
    can_delete = False

# --- ADMIN CLASSES ---

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'branch', 'is_verified')
    list_filter = ('role', 'branch', 'is_verified')
    search_fields = ('username', 'email', 'student_id')

@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(CourseRequest)
class CourseRequestAdmin(admin.ModelAdmin):
    list_display = ('student', 'branch', 'status')
    list_filter = ('status', 'branch')
    actions = ['approve_requests', 'reject_requests']

    def approve_requests(self, request, queryset):
        queryset.update(status='Approved')
    approve_requests.short_description = "Approve selected requests"

    def reject_requests(self, request, queryset):
        queryset.update(status='Rejected')
    reject_requests.short_description = "Reject selected requests"

@admin.register(StudyMaterial)
class StudyMaterialAdmin(admin.ModelAdmin):
    list_display = ('title', 'branch', 'classification', 'is_preview')
    list_filter = ('branch', 'classification', 'is_preview')

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('text_preview', 'category', 'marks', 'created_at')
    list_filter = ('category', 'marks')
    search_fields = ('text',)
    inlines = [ChoiceInline]

    def text_preview(self, obj):
        return obj.text[:50] + "..." if len(obj.text) > 50 else obj.text

@admin.register(MockTest)
class MockTestAdmin(admin.ModelAdmin):
    list_display = ('id', 'student', 'score', 'total_questions', 'is_completed', 'created_at')
    list_filter = ('is_completed', 'created_at')
    search_fields = ('student__username', 'student__email')
    readonly_fields = ('created_at', 'completed_at', 'score', 'total_questions', 'time_limit_minutes')
    inlines = [MockTestQuestionInline]

    def has_add_permission(self, request):
        return False 
@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at')