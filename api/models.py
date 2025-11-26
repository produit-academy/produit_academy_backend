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

class Quiz(models.Model):
    title = models.CharField(max_length=200)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='quizzes')
    duration_minutes = models.IntegerField(default=180) # 3 Hours for GATE
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.title

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    text = models.TextField()
    marks = models.IntegerField(default=1)

    def __str__(self): return str(self.text)[:50]

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    text = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)

    def __str__(self): return self.text

class QuizSubmission(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    score = models.FloatField()
    submitted_at = models.DateTimeField(auto_now_add=True)