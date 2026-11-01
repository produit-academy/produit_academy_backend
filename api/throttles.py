from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class AuthRateThrottle(AnonRateThrottle):
    """Rate limit for authentication and login endpoints to prevent brute-force and credential stuffing."""
    scope = 'auth'


class OTPRateThrottle(AnonRateThrottle):
    """Rate limit for OTP request, resend, and verification endpoints."""
    scope = 'otp'

