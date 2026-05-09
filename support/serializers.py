from rest_framework import serializers
from api.models import Complaint, ContactInquiry


class ComplaintSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.username', read_only=True)
    student_platform = serializers.CharField(source='student.platform', read_only=True)
    class Meta:
        model = Complaint
        fields = ['id', 'student', 'student_name', 'student_platform', 'subject', 'description', 'status', 'resolution_comment', 'created_at', 'resolved_at']
        read_only_fields = ['student', 'created_at', 'resolved_at']


class ContactInquirySerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInquiry
        fields = '__all__'
