from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.views.static import serve

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