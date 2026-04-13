from api.models import (
    Complaint as BaseComplaint,
    ContactInquiry as BaseContactInquiry,
)


class Complaint(BaseComplaint):
    class Meta:
        proxy = True
        verbose_name = 'Complaint'
        verbose_name_plural = 'Complaints'


class ContactInquiry(BaseContactInquiry):
    class Meta:
        proxy = True
        verbose_name = 'Contact Inquiry'
        verbose_name_plural = 'Contact Inquiries'
