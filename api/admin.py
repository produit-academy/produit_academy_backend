from django.contrib import admin
from .models import User, Branch, StudyMaterial, CourseRequest, Session, Quiz, Question, Choice, QuizSubmission

# --- Inline Classes (Allows adding Questions inside Quiz view) ---
class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 4 # Shows 4 option slots by default

class QuestionInline(admin.StackedInline):
    model = Question
    extra = 1

class QuestionAdmin(admin.ModelAdmin):
    inlines = [ChoiceInline]

class QuizAdmin(admin.ModelAdmin):
    inlines = [QuestionInline]
    list_display = ('title', 'branch', 'duration_minutes')

# --- Register Models ---
admin.site.register(User)
admin.site.register(Branch)
admin.site.register(StudyMaterial)
admin.site.register(CourseRequest)
admin.site.register(Session)

# Register new Quiz models
admin.site.register(Quiz, QuizAdmin)
admin.site.register(Question, QuestionAdmin)
admin.site.register(Choice)
admin.site.register(QuizSubmission)