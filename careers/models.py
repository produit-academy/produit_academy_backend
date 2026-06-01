from django.db import models

class JobApplication(models.Model):
    name = models.CharField(max_length=150)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    position = models.CharField(max_length=100)
    portfolio = models.TextField(blank=True, null=True)
    
    # Teacher specific fields
    preferred_courses = models.CharField(max_length=500, blank=True, null=True)
    experience = models.CharField(max_length=200, blank=True, null=True)
    education = models.CharField(max_length=200, blank=True, null=True)
    current_status = models.CharField(max_length=50, blank=True, null=True) # studying, passed_out
    academy_details = models.CharField(max_length=200, blank=True, null=True)
    
    declaration = models.BooleanField(default=False)
    interviewed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.position}"