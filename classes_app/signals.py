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
def trigger_class_completion_wallet_credit(sender, instance, **kwargs):
    if instance.status == 'Completed' and not instance.is_wallet_credited:
        try:
            from .services.wallet_service import credit_teacher_for_completed_session
            credit_teacher_for_completed_session(instance.pk)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error crediting wallet for session #{instance.pk}: {e}")

