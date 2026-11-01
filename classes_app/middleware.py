from django.conf import settings

class ClearHSTSMiddleware:
    """
    Ensures standard security headers are present on all HTTP responses and handles
    HSTS clearing during local development.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Baseline security headers on all responses
        if 'X-Content-Type-Options' not in response:
            response['X-Content-Type-Options'] = 'nosniff'

        if 'X-Frame-Options' not in response:
            response['X-Frame-Options'] = 'DENY'

        if 'Referrer-Policy' not in response:
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        if 'Permissions-Policy' not in response:
            response['Permissions-Policy'] = 'camera=(self), microphone=(self), geolocation=()'

        if 'Content-Security-Policy' not in response:
            response['Content-Security-Policy'] = "default-src 'self' https: data: blob: 'unsafe-inline'; frame-ancestors 'none';"

        # HSTS handling: clear on local debug, enforce in production over HTTPS
        if getattr(settings, 'DEBUG', False):
            response['Strict-Transport-Security'] = 'max-age=0'
        elif getattr(settings, 'SECURE_HSTS_SECONDS', 0) > 0:
            hsts_val = f"max-age={settings.SECURE_HSTS_SECONDS}"
            if getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False):
                hsts_val += "; includeSubDomains"
            if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
                hsts_val += "; preload"
            response['Strict-Transport-Security'] = hsts_val

        return response
