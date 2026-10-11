from django.conf import settings

class ClearHSTSMiddleware:
    """
    In local development (DEBUG=True), sends Strict-Transport-Security: max-age=0
    to automatically force browsers to clear any cached HSTS policies for 127.0.0.1 / localhost.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if getattr(settings, 'DEBUG', False):
            response['Strict-Transport-Security'] = 'max-age=0'
        return response
