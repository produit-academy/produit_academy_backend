from rest_framework import serializers
from api.models import StaffProfile, StaffTask, TaskComment


class StaffProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)
    full_name = serializers.SerializerMethodField()
    role = serializers.CharField(source='user.role', read_only=True)
    phone_number = serializers.CharField(source='user.phone_number', read_only=True)

    class Meta:
        model = StaffProfile
        fields = ['id', 'email', 'full_name', 'role', 'phone_number', 'designation', 'profile_picture', 'bio', 'joined_at']

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.email


class TaskCommentSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskComment
        fields = ['id', 'task', 'author_email', 'author_name', 'text', 'created_at']
        read_only_fields = ['task', 'author_email', 'author_name', 'created_at']
    def get_author_name(self, obj):
        return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.email


class StaffTaskSerializer(serializers.ModelSerializer):
    comments = TaskCommentSerializer(many=True, read_only=True)
    assigned_to_email = serializers.EmailField(source='assigned_to.email', read_only=True)
    assigned_by_email = serializers.EmailField(source='assigned_by.email', read_only=True)

    class Meta:
        model = StaffTask
        fields = [
            'id', 'title', 'description', 'status', 'remarks',
            'due_date', 'created_at', 'completed_at',
            'assigned_to', 'assigned_to_email',
            'assigned_by', 'assigned_by_email',
            'comments'
        ]
        read_only_fields = ['created_at', 'assigned_by', 'assigned_by_email', 'assigned_to_email']
