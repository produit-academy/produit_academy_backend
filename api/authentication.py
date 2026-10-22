from django.core.cache import cache
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Session

class SingleSessionJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        
        user = self.get_user(validated_token)
        
        # --- SINGLE SESSION ENFORCEMENT WITH IN-MEMORY CACHE ---
        if user.role == 'student' and not user.is_staff and not user.is_superuser:
            token_str = raw_token.decode('utf-8') if isinstance(raw_token, bytes) else str(raw_token)
            token_session_id = validated_token.get('session_id')
            cache_key = f"user_active_session_{user.id}"
            session_key = cache.get(cache_key)
            
            if session_key is None:
                active_session = Session.objects.filter(user=user).order_by('-created_at').first()
                if not active_session:
                    raise AuthenticationFailed('Invalid session. Please log in again.')
                session_key = str(active_session.session_key)
                cache.set(cache_key, session_key, timeout=300)

            # Compare against session_id claim if present, else fallback to raw token string
            expected_key = token_session_id if token_session_id else token_str
            if session_key != expected_key:
                raise AuthenticationFailed('This session has expired because you logged in on another device.')
            
        return user, validated_token