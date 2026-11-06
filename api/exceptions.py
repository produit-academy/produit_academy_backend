import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

logger = logging.getLogger(__name__)

def custom_drf_exception_handler(exc, context):
    """
    Standardized DRF exception handler that captures uncaught 500 exceptions
    and returns a clean JSON response in production while logging the error.
    """
    response = exception_handler(exc, context)

    if response is None:
        logger.exception("Unhandled exception in API request: %s", exc)
        if settings.DEBUG:
            # During local development, allow Django's detailed debug traceback
            return None
        return Response(
            {
                "error": "Internal Server Error",
                "detail": "An unexpected server error occurred. Please try again later."
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    return response

