from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Session

class SessionEnforcedJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)

        if user.role == 'student':
            # We use the raw token string as the session key
            token_str = raw_token.decode('utf-8') if isinstance(raw_token, bytes) else str(raw_token)
            try:
                Session.objects.get(user=user, session_key=token_str)
            except Session.DoesNotExist:
                raise AuthenticationFailed('Session expired or invalid. Please login again.')

        return user, validated_token