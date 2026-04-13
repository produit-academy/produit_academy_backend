from django.utils import timezone
from rest_framework import generics, permissions
from rest_framework.views import APIView

from api.models import Complaint, ContactInquiry
from .serializers import ComplaintSerializer, ContactInquirySerializer


# --- COMPLAINT SYSTEM VIEWS ---

class StudentComplaintView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ComplaintSerializer

    def get_queryset(self):
        return Complaint.objects.filter(student=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(student=self.request.user)

class AdminComplaintDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = ComplaintSerializer
    queryset = Complaint.objects.all()

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status == 'Resolved' and not instance.resolved_at:
            instance.resolved_at = timezone.now()
            instance.save()

class AdminComplaintListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = ComplaintSerializer
    queryset = Complaint.objects.all().order_by('-created_at')


# --- CONTACT INQUIRY VIEWS ---

class ContactInquiryView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    queryset = ContactInquiry.objects.all()
    serializer_class = ContactInquirySerializer

class AdminContactListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = ContactInquirySerializer

    def get_queryset(self):
        queryset = ContactInquiry.objects.all().order_by('-created_at')
        platform = self.request.query_params.get('platform')
        if platform:
            queryset = queryset.filter(platform=platform)
        return queryset

class AdminContactUpdateView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = ContactInquiry.objects.all()
    serializer_class = ContactInquirySerializer
