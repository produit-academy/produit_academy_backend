# api/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class Branch(models.Model):
    name = models.CharField(max_length=100)
    def __str__(self):
        return self.name

class User(AbstractUser):
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('admin', 'Admin'),
        ('branch_admin', 'Branch Admin'), 
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student') 
    
    student_id = models.CharField(max_length=100, unique=True, null=True, blank=True)
    college = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    
    branch = models.ForeignKey('Branch', on_delete=models.SET_NULL, null=True, blank=True)

class Session(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

class StudyMaterial(models.Model):
    CLASSIFICATION_CHOICES = (
        ('PYQ', 'PYQ'),
        ('Notes', 'Notes'),
        ('One-shots', 'One-Shots'),
    )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    classification = models.CharField(max_length=50, choices=CLASSIFICATION_CHOICES)
    file = models.FileField(upload_to='materials/')
    is_preview = models.BooleanField(default=False)
    def __str__(self):
        return self.title

class CourseRequest(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    requested_at = models.DateTimeField(auto_now_add=True)

# --- NEW MOCK TEST MODELS ---

class Quiz(models.Model):
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='quizzes')
    title = models.CharField(max_length=255)
    duration_minutes = models.IntegerField(default=30)
    is_active = models.BooleanField(default=False, help_text="Students can only see active quizzes")

    def __str__(self):
        return self.title

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    text = models.TextField()
    marks = models.IntegerField(default=1)

    def __str__(self):
        return self.text[:50]

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return self.text

class StudentResult(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='quiz_results')
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='results')
    score = models.IntegerField()
    total_marks = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.student.username} - {self.quiz.title}'

class StudentAnswer(models.Model):
    result = models.ForeignKey(StudentResult, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    selected_choice = models.ForeignKey(Choice, on_delete=models.CASCADE)
    is_correct = models.BooleanField()