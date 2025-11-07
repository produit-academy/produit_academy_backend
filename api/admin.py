from django.contrib import admin
from .models import *

# Inlines for easy quiz creation
class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 3

class QuestionAdmin(admin.ModelAdmin):
    inlines = [ChoiceInline]
    list_display = ('text', 'quiz', 'marks')
    list_filter = ('quiz',)

class QuestionInline(admin.StackedInline):
    model = Question
    extra = 1
    show_change_link = True

class QuizAdmin(admin.ModelAdmin):
    list_display = ('title', 'branch', 'is_active')
    list_filter = ('branch', 'is_active')
    inlines = [QuestionInline]

class StudentResultAdmin(admin.ModelAdmin):
    list_display = ('student', 'quiz', 'score', 'total_marks', 'timestamp')
    list_filter = ('quiz', 'student')

# Register all your models
admin.site.register(User)
admin.site.register(Branch)
admin.site.register(StudyMaterial)
admin.site.register(CourseRequest)
admin.site.register(Session)

# --- Register new mock test models ---
admin.site.register(Quiz, QuizAdmin)
admin.site.register(Question, QuestionAdmin)
admin.site.register(Choice)
admin.site.register(StudentResult, StudentResultAdmin)
admin.site.register(StudentAnswer)