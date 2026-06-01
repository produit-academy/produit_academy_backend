from django.db import models
from api.models import User


class Course(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class TeacherProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='classes_teacher_profile', limit_choices_to={'role': 'teacher'})
    subjects = models.ManyToManyField(Course, related_name='teachers')
    is_approved = models.BooleanField(default=False)
    hourly_rate = models.DecimalField(
        max_digits=8, decimal_places=2, default=0,
        help_text="Payment rate per hour (₹)"
    )

    def __str__(self):
        return f"Profile: {self.user.username}"

class MentorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='classes_mentor_profile', limit_choices_to={'role': 'mentor'})
    is_approved = models.BooleanField(default=False)
    hourly_rate = models.DecimalField(
        max_digits=8, decimal_places=2, default=0,
        help_text="Payment rate per hour (₹)"
    )

    def __str__(self):
        return f"Mentor Profile: {self.user.username}"


class TeacherAvailability(models.Model):
    """Weekly availability: teacher submits specific dates + time slots each week (by Sunday 6 PM)."""
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='teacher_availabilities', limit_choices_to={'role': 'teacher'})
    date = models.DateField()  # specific date, e.g. 2026-06-02 (Monday)
    start_time = models.TimeField()
    end_time = models.TimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['date', 'start_time']
        unique_together = ('teacher', 'date', 'start_time')  # prevent duplicate slots

    def __str__(self):
        return f"{self.teacher.username} - {self.date} ({self.start_time} to {self.end_time})"


class Enrollment(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='classes_enrollments', limit_choices_to={'role': 'student'})
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='enrollments')
    teacher = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_enrollments', limit_choices_to={'role': 'teacher'})
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_completed = models.BooleanField(default=False)

    class Meta:
        unique_together = ('student', 'course')

    def __str__(self):
        return f"{self.student.username} → {self.course.name}"


class ClassSession(models.Model):
    STATUS_CHOICES = [
        ('Scheduled', 'Scheduled'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
    ]

    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='sessions')
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='taught_sessions', limit_choices_to={'role': 'teacher'})
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attended_sessions', null=True, blank=True, limit_choices_to={'role': 'student'})
    title = models.CharField(max_length=200)
    meeting_link = models.URLField(max_length=500, blank=True, null=True)
    scheduled_time = models.DateTimeField()
    duration_minutes = models.IntegerField(default=60)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Scheduled')
    OUTCOME_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected')
    ]

    is_demo = models.BooleanField(default=False)
    demo_outcome = models.CharField(max_length=20, choices=OUTCOME_CHOICES, default='Pending')
    teacher_notes = models.TextField(blank=True, null=True)
    cancel_reason = models.TextField(blank=True, null=True)
    cancelled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='cancelled_sessions')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-scheduled_time']

    def __str__(self):
        return f"{self.title} ({self.course.name})"


class AttendanceRecord(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('Late', 'Late'),
    ]

    class_session = models.ForeignKey(ClassSession, on_delete=models.CASCADE, related_name='attendance')
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='class_attendance')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    marked_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='marked_attendance'
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('class_session', 'student')

    def __str__(self):
        return f"{self.student.username} - {self.status} ({self.class_session.title})"
