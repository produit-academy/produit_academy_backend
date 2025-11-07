from django.contrib import admin
from .models import User, Branch, StudyMaterial, CourseRequest, Session

admin.site.register(User)
admin.site.register(Branch)
admin.site.register(StudyMaterial)
admin.site.register(CourseRequest)
admin.site.register(Session)