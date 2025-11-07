from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

class User(AbstractUser):
    ROLE_CHOICES = (('student', 'Student'), ('admin', 'Admin'))
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='student')
    student_id = models.CharField(max_length=20, unique=True, null=True, blank=True)
    branch = models.ForeignKey('Branch', on_delete=models.SET_NULL, null=True, blank=True)
    groups = models.ManyToManyField('auth.Group', related_name='api_user_set', blank=True)
    user_permissions = models.ManyToManyField('auth.Permission', related_name='api_user_set_permissions', blank=True)
    is_verified = models.BooleanField(default=False)
    college = models.CharField(max_length=200, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    otp = models.CharField(max_length=4, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)

class Branch(models.Model):
    name = models.CharField(max_length=100)
    def __str__(self): return self.name

class StudyMaterial(models.Model):
    CLASSIFICATION_CHOICES = (('PYQ', 'PYQ'), ('Notes', 'Notes'), ('One-shots', 'One-shots'))
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='materials/')
    classification = models.CharField(max_length=10, choices=CLASSIFICATION_CHOICES)
    branch = models.ForeignKey('Branch', on_delete=models.CASCADE)
    is_preview = models.BooleanField(default=False)
    def __str__(self): return self.title

class CourseRequest(models.Model):
    STATUS_CHOICES = (('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected'))
    student = models.ForeignKey('User', on_delete=models.CASCADE)
    branch = models.ForeignKey('Branch', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    def __str__(self): return f"{self.student.username} - {self.branch.name} ({self.status})"

class Session(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # Use TextField as the primary key to guarantee enough space
    session_key = models.TextField(primary_key=True) 
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s session"