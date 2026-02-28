# careers/admin.py
from django.contrib import admin
from .models import JobApplication

@admin.register(JobApplication)
class JobApplicationAdmin(admin.ModelAdmin):
    # The columns that will show up in the admin list view
    list_display = ('name', 'position', 'email', 'phone', 'created_at')
    
    # Adds a filter sidebar to filter by role or date
    list_filter = ('position', 'created_at')
    
    # Adds a search bar to find candidates by name, email, or role
    search_fields = ('name', 'email', 'position')
    
    # Prevents accidental edits to the submission timestamp
    readonly_fields = ('created_at',)