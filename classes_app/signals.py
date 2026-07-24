from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from .models import ClassSession
from api.views import send_html_email

@receiver(pre_save, sender=ClassSession)
def cache_previous_link(sender, instance, **kwargs):
    if instance.pk:
        try:
            old_instance = ClassSession.objects.get(pk=instance.pk)
            instance._old_meeting_link = old_instance.meeting_link
        except ClassSession.DoesNotExist:
            instance._old_meeting_link = None
    else:
        instance._old_meeting_link = None

@receiver(post_save, sender=ClassSession)
def trigger_demo_emails(sender, instance, created, **kwargs):
    if instance.is_demo and not created:
        old_link = getattr(instance, '_old_meeting_link', None)
        new_link = instance.meeting_link

        if not old_link and new_link:
            # The teacher just added the link. Send email to student.
            try:
                send_html_email(
                    subject='Your Demo Class is Confirmed!',
                    recipient_email=instance.student.email,
                    username=instance.student.first_name or instance.student.email.split('@')[0],
                    type='demo_link',
                    time=instance.scheduled_time.strftime("%A, %b %d at %I:%M %p"),
                    link=new_link,
                    teacher_name=instance.teacher.first_name or 'Your Teacher'
                )
            except Exception as e:
                print(f"Error sending student demo link: {e}")
