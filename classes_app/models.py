from django.db import models
from api.models import User


class Course(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Subject(models.Model):
    """Subjects within a course/class (e.g., Mathematics within CBSE Class 10)."""
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='subjects')
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text="Emoji or icon identifier")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('course', 'name')
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.course.name})"


class TeacherProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='classes_teacher_profile', limit_choices_to={'role': 'teacher'})
    subjects = models.ManyToManyField(Course, related_name='teachers', blank=True)
    taught_subjects = models.ManyToManyField(Subject, related_name='teachers', blank=True)
    is_approved = models.BooleanField(default=False)
    hourly_rate = models.DecimalField(
        max_digits=8, decimal_places=2, default=0,
        help_text="Fee per class (₹) - set by HR"
    )

    # Extended profile fields
    bio = models.TextField(blank=True, help_text="Teacher's detailed biography")
    qualification = models.CharField(max_length=300, blank=True)
    experience = models.CharField(max_length=200, blank=True, help_text="e.g., 5+ years")
    skills = models.TextField(blank=True, help_text="Comma-separated skills")
    certifications = models.TextField(blank=True)
    languages = models.CharField(max_length=300, blank=True, help_text="Languages known")
    teaching_style = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='teacher_profiles/', blank=True, null=True)
    profile_picture_base64 = models.TextField(blank=True, null=True, help_text="Base64 encoded WebP image")
    google_meet_link = models.URLField(max_length=500, blank=True, help_text="Permanent Google Meet URL")

    def __str__(self):
        return f"Profile: {self.user.username}"


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
        ('Live', 'Live / Active'),
        ('Completed', 'Completed'),
        ('Not Conducted', 'Not Conducted'),
        ('Cancelled', 'Cancelled'),
        ('Needs Review', 'Expired / Needs Review'),
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
    
    # Class outcome tracking
    outcome_remarks = models.TextField(blank=True, default='')
    outcome_marked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='marked_session_outcomes')
    outcome_marked_at = models.DateTimeField(null=True, blank=True)

    # Google Meet link audit
    meet_link_added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='added_meet_links')
    meet_link_updated_at = models.DateTimeField(null=True, blank=True)

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


# --- NEW MODELS ---

class TeacherDemoVideo(models.Model):
    """Demo videos uploaded/linked by teachers for their public profile."""
    VIDEO_TYPE_CHOICES = [
        ('youtube', 'YouTube'),
        ('vimeo', 'Vimeo'),
        ('upload', 'Uploaded'),
    ]
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='demo_videos', limit_choices_to={'role': 'teacher'})
    title = models.CharField(max_length=200)
    video_url = models.URLField(max_length=500)
    video_type = models.CharField(max_length=10, choices=VIDEO_TYPE_CHOICES, default='youtube')
    thumbnail_url = models.URLField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order', '-created_at']

    def __str__(self):
        return f"{self.title} - {self.teacher.username}"


PLATFORM_FEE = 50  # ₹50 platform fee per booking


class Booking(models.Model):
    """Student booking of a teacher for a subject."""
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('advance_paid', 'Advance Paid'),
        ('fully_paid', 'Fully Paid'),
    ]
    BOOKING_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed'),
    ]

    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings', limit_choices_to={'role': 'student'})
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='teacher_bookings', limit_choices_to={'role': 'teacher'})
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='bookings')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='bookings')
    start_date = models.DateField()
    end_date = models.DateField()
    preferred_time = models.TimeField()
    num_classes = models.PositiveIntegerField()

    # Fee breakdown
    teacher_fee_per_class = models.DecimalField(max_digits=8, decimal_places=2, help_text="Snapshot of teacher rate at booking time")
    platform_fee = models.DecimalField(max_digits=8, decimal_places=2, default=PLATFORM_FEE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    advance_amount = models.DecimalField(max_digits=10, decimal_places=2)
    remaining_amount = models.DecimalField(max_digits=10, decimal_places=2)

    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    booking_status = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES, default='pending')
    google_meet_link = models.URLField(max_length=500, blank=True)

    # Razorpay tracking
    razorpay_order_id = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Booking: {self.student.username} → {self.teacher.username} ({self.subject.name})"


class BookingSchedule(models.Model):
    """Individual class schedule entries generated after a booking is confirmed."""
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('live', 'Live / Active'),
        ('completed', 'Completed'),
        ('not_conducted', 'Not Conducted'),
        ('cancelled', 'Cancelled'),
        ('needs_review', 'Expired / Needs Review'),
    ]

    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='schedules')
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    cancel_reason = models.TextField(blank=True, default='')
    cancelled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='cancelled_schedules')
    cancelled_at = models.DateTimeField(null=True, blank=True)
    class_session = models.OneToOneField(ClassSession, on_delete=models.SET_NULL, null=True, blank=True, related_name='booking_schedule')

    class Meta:
        ordering = ['date', 'start_time']

    def __str__(self):
        return f"Schedule: {self.booking} on {self.date}"


class EmailLog(models.Model):
    """Logs of all emails sent by the platform."""
    STATUS_CHOICES = [
        ('sent', 'Sent'),
        ('failed', 'Failed'),
    ]

    recipient_email = models.EmailField()
    subject = models.CharField(max_length=300)
    email_type = models.CharField(max_length=50)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='sent')
    error_message = models.TextField(blank=True)
    related_booking = models.ForeignKey(Booking, on_delete=models.SET_NULL, null=True, blank=True, related_name='email_logs')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.email_type} → {self.recipient_email} ({self.status})"


class PaymentTransaction(models.Model):
    """Audit log for all Razorpay payment attempts and webhook updates."""
    STATUS_CHOICES = [
        ('created', 'Created'),
        ('captured', 'Captured'),
        ('failed', 'Failed'),
    ]

    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='payment_transactions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='classes_payment_transactions')
    razorpay_order_id = models.CharField(max_length=100, db_index=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, help_text="Amount in INR")
    currency = models.CharField(max_length=10, default='INR')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='created')
    error_code = models.CharField(max_length=100, blank=True, null=True)
    error_description = models.TextField(blank=True, null=True)
    raw_response = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.razorpay_order_id} - {self.status} (₹{self.amount})"


class ClassReport(models.Model):
    """Teacher class & student analysis report."""
    REPORT_TYPE_CHOICES = [
        ('individual', 'Individual Student'),
        ('cohort', 'Class Cohort'),
    ]
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('reviewed', 'Reviewed'),
        ('approved', 'Approved'),
    ]

    class_session = models.ForeignKey(ClassSession, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submitted_reports', limit_choices_to={'role': 'teacher'})
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_reports', null=True, blank=True, limit_choices_to={'role': 'student'})
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='individual')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='submitted')

    # Qualitative & Quantitative observations
    performance_rating = models.PositiveSmallIntegerField(default=5, help_text="Rating out of 10")
    attendance_observation = models.CharField(max_length=100, blank=True, default='Present')
    homework_completion = models.CharField(
        max_length=30,
        choices=[
            ('completed', 'Completed'),
            ('partial', 'Partially Completed'),
            ('not_done', 'Not Completed'),
            ('not_assigned', 'Not Assigned'),
        ],
        default='completed'
    )
    strengths = models.TextField(blank=True, default='')
    areas_for_improvement = models.TextField(blank=True, default='')
    recommendations = models.TextField(blank=True, default='')
    text_report = models.TextField(blank=True, default='')
    
    # Uploaded media
    pdf_report = models.FileField(upload_to='reports/pdf/', blank=True, null=True)
    voice_note = models.FileField(upload_to='reports/audio/', blank=True, null=True)
    voice_note_duration = models.IntegerField(null=True, blank=True, help_text="Duration in seconds")

    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_reports')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        target = self.student.username if self.student else "Cohort"
        return f"Report by {self.teacher.username} for {target} ({self.created_at.strftime('%Y-%m-%d')})"


class DailyClassVoiceNote(models.Model):
    """Daily voice note recorded by a teacher for a class session."""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
    ]

    class_session = models.ForeignKey(ClassSession, on_delete=models.CASCADE, related_name='voice_notes')
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='daily_voice_notes', limit_choices_to={'role': 'teacher'})
    student = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='student_voice_notes', limit_choices_to={'role': 'student'})
    date = models.DateField(auto_now_add=True)
    audio_file = models.FileField(upload_to='voice_notes/')
    text_summary = models.TextField(blank=True, default='')
    duration_seconds = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='submitted')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Voice Note: {self.teacher.username} - {self.class_session.title} ({self.created_at.strftime('%Y-%m-%d')})"


class TeacherMonthlyReport(models.Model):
    """Monthly final report submitted by teachers with aggregate observations."""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('reviewed', 'Reviewed'),
        ('approved', 'Approved'),
    ]

    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='monthly_reports', limit_choices_to={'role': 'teacher'})
    month = models.PositiveSmallIntegerField(help_text="Month number 1-12")
    year = models.PositiveSmallIntegerField(help_text="e.g. 2026")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='submitted')

    # Aggregated metrics
    classes_conducted_count = models.PositiveIntegerField(default=0)
    classes_not_conducted_count = models.PositiveIntegerField(default=0)
    total_teaching_hours = models.DecimalField(max_digits=7, decimal_places=2, default=0.00)
    attendance_summary = models.JSONField(default=dict, blank=True, help_text="Summary breakdown of attendance")

    # Detailed remarks
    student_progress_notes = models.TextField(blank=True, default='')
    tasks_assigned_completed = models.TextField(blank=True, default='')
    important_observations = models.TextField(blank=True, default='')
    voice_notes_count = models.PositiveIntegerField(default=0)
    overall_remarks = models.TextField(blank=True, default='')
    next_month_recommendations = models.TextField(blank=True, default='')
    pdf_report_file = models.FileField(upload_to='monthly_reports/pdf/', blank=True, null=True)

    submitted_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_monthly_reports')
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-year', '-month']
        unique_together = ('teacher', 'year', 'month')

    def __str__(self):
        return f"Monthly Report: {self.teacher.username} ({self.month}/{self.year}) - {self.status}"

