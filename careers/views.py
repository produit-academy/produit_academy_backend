# careers/views.py
from rest_framework import generics, permissions
from django.core.mail import send_mail
from django.conf import settings
from .models import JobApplication
from .serializers import JobApplicationSerializer

class JobApplicationCreateView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny] 
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer

    def perform_create(self, serializer):
        # 1. Save the application to the database first
        application = serializer.save()

        # 2. Prepare the Email Content
        subject = "Application Received - Produit Academy Careers"
        
        # Plain text fallback
        message = f"Hi {application.name},\n\nThank you for applying for the {application.position} role at Produit Academy! We have received your application and will review it shortly.\n\nBest regards,\nThe Produit Academy Team"
        
        html_message = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
            <h2 style="color: #228B22; text-align: center;">Application Received!</h2>
            <p>Hi <strong>{application.name}</strong>,</p>
            <p>Thank you for applying for the <strong>{application.position}</strong> position at Produit Academy.</p>
            <p>We have successfully received your application. Our team will review your details and portfolio, and we will get back to you if your profile matches our current requirements.</p>
            <br>
            <p>Best regards,<br><strong>The Produit Academy Team</strong></p>
        </div>
        """

        # 3. Send the Email
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[application.email],
                html_message=html_message,
                fail_silently=True
            )
        except Exception as e:
            print(f"Careers Email Error: {e}")