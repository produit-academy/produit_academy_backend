from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

# --- CORE MODELS ---
class Branch(models.Model):
    name = models.CharField(max_length=100)
    
    def __str__(self): 
        return self.name

class User(AbstractUser):
    ROLE_CHOICES = (('student', 'Student'), ('admin', 'Admin'), ('mentor', 'Mentor'), ('teacher', 'Teacher'), ('staff', 'Staff'), ('manager', 'Manager'))
    PLATFORM_CHOICES = (('gate', 'GATE'), ('classes', 'Classes'))
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='student')
    platform = models.CharField(max_length=10, choices=PLATFORM_CHOICES, default='gate')
    student_id = models.CharField(max_length=20, unique=True, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True)
    college = models.CharField(max_length=200, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    current_class = models.CharField(max_length=50, blank=True, null=True)
    school_name = models.CharField(max_length=200, blank=True, null=True)
    assigned_mentor = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='mentored_students', limit_choices_to={'role': 'mentor'}
    )
    assigned_teacher = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='taught_students', limit_choices_to={'role': 'teacher'}
    )
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True) 
    otp_expiry = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

# --- COURSE & MATERIAL MODELS ---

class StudyMaterial(models.Model):
    CLASSIFICATION_CHOICES = (('PYQ', 'PYQ'), ('Notes', 'Notes'), ('One-shots', 'One-shots'))
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='materials/')
    classification = models.CharField(max_length=10, choices=CLASSIFICATION_CHOICES)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
    is_preview = models.BooleanField(default=False)

    def __str__(self): 
        return self.title

class CourseRequest(models.Model):
    STATUS_CHOICES = (('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected'))
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')

    def __str__(self): 
        return f"{self.student.username} - {self.branch.name} ({self.status})"

# --- SECURITY MODELS ---

class Session(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.TextField(primary_key=True) 
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s active session"

# --- QUESTION BANK & MOCK TEST MODELS ---

class Question(models.Model):
    CATEGORY_CHOICES = (
        ('General Aptitude', 'General Aptitude'),
        ('Engineering Mathematics', 'Engineering Mathematics'),
        ('Subject Paper', 'Subject Paper')
    )
    
    TYPE_CHOICES = (
        ('MCQ', 'Multiple Choice Question'),
        ('MSQ', 'Multiple Select Question'),
        ('NAT', 'Numerical Answer Type')
    )
    
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Subject Paper')
    question_type = models.CharField(max_length=3, choices=TYPE_CHOICES, default='MCQ')
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True)
    text = models.TextField(blank=True, null=True)
    image = models.TextField(blank=True, null=True)
    marks = models.IntegerField(default=1)
    
    # For NAT questions
    nat_min = models.FloatField(blank=True, null=True)
    nat_max = models.FloatField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): 
        return f"{self.question_type} - {str(self.text)[:50]}"

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    text = models.CharField(max_length=200, blank=True, null=True)
    image = models.TextField(blank=True, null=True)
    is_correct = models.BooleanField(default=False)

    def __str__(self): 
        return self.text

class MockTest(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mock_tests')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_questions = models.IntegerField()
    time_limit_minutes = models.IntegerField()
    score = models.FloatField(default=0.0)
    is_completed = models.BooleanField(default=False)

    def __str__(self): 
        return f"Test {self.id} - {self.student.username}"

class MockTestQuestion(models.Model):
    mock_test = models.ForeignKey(MockTest, on_delete=models.CASCADE, related_name='test_questions')
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    
    # For MCQ
    selected_choice = models.ForeignKey(Choice, on_delete=models.SET_NULL, null=True, blank=True, related_name='selected_in_mcq')
    
    # For MSQ (Many-to-Many to allow multiple selections)
    selected_choices = models.ManyToManyField(Choice, blank=True, related_name='selected_in_msq')
    
    # For NAT
    nat_answer = models.FloatField(blank=True, null=True)
    
    is_correct = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ('mock_test', 'question')

# --- COMPLAINT SYSTEM MODELS ---

class Complaint(models.Model):
    STATUS_CHOICES = (('Pending', 'Pending'), ('Resolved', 'Resolved'))
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    subject = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    resolution_comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.subject} - {self.student.username}"

class ContactInquiry(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=15)
    platform = models.CharField(max_length=10, choices=[('gate', 'GATE'), ('classes', 'Classes')], default='gate')
    course = models.CharField(max_length=100) # This will store the Exam Category
    message = models.TextField()
    status = models.CharField(max_length=20, choices=(('Pending', 'Pending'), ('Resolved', 'Resolved')), default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.course}"

# --- STAFF MODELS ---

class StaffProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='staff_profile',
        limit_choices_to={'role': 'staff'}
    )
    designation = models.CharField(max_length=100, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='staff_profiles/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Staff Profile - {self.user.email}"


class StaffTask(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='assigned_tasks',
        limit_choices_to={'role': 'staff'}
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='created_tasks',
        limit_choices_to={'role': 'admin'}
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    remarks = models.TextField(blank=True, null=True)
    due_date = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    payment_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    def __str__(self):
        return f"{self.title} → {self.assigned_to.email} [{self.status}]"


class TaskComment(models.Model):
    task = models.ForeignKey(StaffTask, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.email} on Task {self.task.id}"
    
# --- WALLET MODELS ---

class StaffWallet(models.Model):
    staff = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='wallet',
        limit_choices_to={'role': 'staff'}
    )
    total_earned = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def balance(self):
        return self.total_earned - self.total_paid

    def __str__(self):
        return f"Wallet - {self.staff.email} | Balance: {self.balance}"


class WalletTransaction(models.Model):
    TYPE_CHOICES = (
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    )
    wallet = models.ForeignKey(StaffWallet, on_delete=models.CASCADE, related_name='transactions')
    task = models.ForeignKey(StaffTask, on_delete=models.SET_NULL, null=True, blank=True, related_name='payment')
    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    note = models.CharField(max_length=200, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.type} ₹{self.amount} - {self.wallet.staff.email}"