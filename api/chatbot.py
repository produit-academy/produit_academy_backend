"""
Endpoints used by the separately deployed learning-assistant chatbot.

  GET /api/chatbot/token/              (student's normal JWT)  -> short-lived chatbot token
  GET /api/chatbot/profile/?student_id=  (X-Service-Key)       -> profile for the chatbot
  GET /api/chatbot/progress/?student_id= (X-Service-Key)       -> mock-test / class progress

Everything stays disabled (503) until CHATBOT_JWT_SECRET / CHATBOT_SERVICE_KEY are set.
"""
import hmac
import time

import jwt
from django.conf import settings
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User, MockTest, MockTestQuestion

CHATBOT_TOKEN_LIFETIME_SECONDS = 15 * 60


class ChatbotTokenView(APIView):
    """Exchange the logged-in student's site token for a chatbot token (sub = user id)."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not settings.CHATBOT_JWT_SECRET:
            return Response({'detail': 'Chatbot is not configured.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        user = request.user
        if user.role != 'student' or user.is_staff or user.is_superuser:
            return Response({'detail': 'The assistant is available to students only.'}, status=status.HTTP_403_FORBIDDEN)
        token = jwt.encode(
            {'sub': str(user.id), 'name': user.first_name or user.username,
             'exp': int(time.time()) + CHATBOT_TOKEN_LIFETIME_SECONDS},
            settings.CHATBOT_JWT_SECRET, algorithm='HS256')
        return Response({'token': token})


class HasChatbotServiceKey(permissions.BasePermission):
    def has_permission(self, request, view):
        expected = settings.CHATBOT_SERVICE_KEY
        given = request.headers.get('X-Service-Key', '')
        return bool(expected) and hmac.compare_digest(given, expected)


class _ChatbotServiceView(APIView):
    # Server-to-server calls: no user JWT, and no per-IP throttling (all chatbot
    # traffic arrives from the one chatbot server IP).
    authentication_classes = []
    permission_classes = [HasChatbotServiceKey]
    throttle_classes = []

    def get_student(self, request):
        sid = request.query_params.get('student_id', '')
        if not str(sid).isdigit():
            return None
        return User.objects.filter(pk=int(sid), role='student').select_related('branch').first()


class ChatbotProfileView(_ChatbotServiceView):
    def get(self, request):
        user = self.get_student(request)
        if not user:
            return Response({'detail': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)

        profile = {
            'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            'platform': user.platform,
            'phone_number': user.phone_number or '',
            'member_since': user.date_joined.date().isoformat(),
        }
        if user.student_id:  # internal id: shown when present, never asked for
            profile['student_id'] = user.student_id
        # Only the fields each platform actually collects, so the assistant
        # never asks a Classes student for a college (or vice versa).
        if user.platform == 'classes':
            profile['current_class'] = user.current_class or ''
            profile['school_name'] = user.school_name or ''
        else:
            profile['college'] = user.college or ''
            profile['branch'] = user.branch.name if user.branch else ''
        return Response(profile)


class ChatbotProgressView(_ChatbotServiceView):
    def get(self, request):
        user = self.get_student(request)
        if not user:
            return Response({'detail': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)

        # GATE: per-category percentage for each completed mock test, oldest first.
        tests = list(MockTest.objects.filter(student=user, is_completed=True)
                     .order_by('completed_at').values('id', 'score', 'completed_at')[:50])
        per_test = {}
        rows = (MockTestQuestion.objects.filter(mock_test_id__in=[t['id'] for t in tests])
                .values('mock_test_id', 'question__category', 'is_correct'))
        for r in rows:
            cat = r['question__category'] or 'Uncategorized'
            stats = per_test.setdefault(r['mock_test_id'], {}).setdefault(cat, [0, 0])
            stats[0] += 1
            stats[1] += 1 if r['is_correct'] else 0
        topics = {}
        for t in tests:
            for cat, (total, correct) in per_test.get(t['id'], {}).items():
                topics.setdefault(cat, []).append(round(100 * correct / total))

        data = {
            'topics': [{'topic': k, 'quiz_scores': v} for k, v in topics.items()],
            'mock_tests_completed': len(tests),
            'recent_mock_test_scores': [t['score'] for t in tests[-5:]],
        }

        if user.platform == 'classes':
            from classes_app.models import Enrollment, ClassSession, AttendanceRecord
            from django.utils import timezone
            enrollments = Enrollment.objects.filter(student=user).select_related('course', 'teacher')
            data['enrolled_courses'] = [{
                'course': e.course.name,
                'teacher': (f"{e.teacher.first_name} {e.teacher.last_name}".strip() if e.teacher else ''),
                'completed': e.is_completed,
            } for e in enrollments]
            data['upcoming_classes'] = ClassSession.objects.filter(
                student=user, status='Scheduled', scheduled_time__gte=timezone.now()).count()
            marked = AttendanceRecord.objects.filter(student=user)
            total = marked.count()
            if total:
                present = marked.filter(status__in=['Present', 'Late']).count()
                data['attendance_percent'] = round(100 * present / total)
        return Response(data)
