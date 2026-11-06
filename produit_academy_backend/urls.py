from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.views.static import serve
from django.http import JsonResponse

def custom_bad_request_view(request, exception=None):
    return JsonResponse({'error': 'Bad Request', 'detail': 'Invalid request parameters.'}, status=400)

def custom_permission_denied_view(request, exception=None):
    return JsonResponse({'error': 'Permission Denied', 'detail': 'You do not have permission to access this resource.'}, status=403)

def custom_page_not_found_view(request, exception=None):
    return JsonResponse({'error': 'Not Found', 'detail': 'The requested endpoint was not found.'}, status=404)

def custom_server_error_view(request):
    return JsonResponse({'error': 'Internal Server Error', 'detail': 'An unexpected server error occurred.'}, status=500)

handler400 = 'produit_academy_backend.urls.custom_bad_request_view'
handler403 = 'produit_academy_backend.urls.custom_permission_denied_view'
handler404 = 'produit_academy_backend.urls.custom_page_not_found_view'
handler500 = 'produit_academy_backend.urls.custom_server_error_view'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),           # Core Auth & User Management
    path('api/', include('gate.urls')),           # GATE Platform (mock tests, questions, materials)
    path('api/', include('staff_mgmt.urls')),     # Staff Management (tasks, profiles)
    path('api/', include('support.urls')),        # Support System (complaints, contacts)
    path('api/classes/', include('classes_app.urls')),
    path('careers/', include('careers.urls')),
]

# Only serve media locally during local development; in production Cloudinary handles media
if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)