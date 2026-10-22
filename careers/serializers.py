from rest_framework import serializers
from .models import JobApplication

class JobApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobApplication
        fields = '__all__'


class PublicJobApplicationSerializer(JobApplicationSerializer):
    """Used by the public application form: applicants cannot set review fields."""
    class Meta(JobApplicationSerializer.Meta):
        read_only_fields = ('interviewed', 'created_at')