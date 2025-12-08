from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Session

class SingleSessionJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get the standard JWT authentication result
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        
        # Standard user resolution
        user = self.get_user(validated_token)
        
        # --- SINGLE SESSION ENFORCEMENT ---
        # Only enforce for STUDENTS. Admins are exempt.
        if user.role == 'student':
            try:
                # We compare the string representation of the token
                active_session = Session.objects.get(user=user)
                token_str = raw_token.decode('utf-8') if isinstance(raw_token, bytes) else str(raw_token)
                
                if str(active_session.session_key) != token_str:
                    raise AuthenticationFailed('This session has expired because you logged in on another device.')
            except Session.DoesNotExist:
                # If it IS a student but no session found, it might be an old token or manual deletion.
                # Fail strictly: student MUST have a session record if they logged in via our view.
                raise AuthenticationFailed('Invalid session. Please log in again.')
            
        return user, validated_token