import os
from pathlib import Path
from datetime import timedelta
import dj_database_url
from dotenv import load_dotenv

load_dotenv(override=True)

BASE_DIR = Path(__file__).resolve().parent.parent

# --- SECURITY CONFIGURATION ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-dev-key')
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
if not DEBUG and (SECRET_KEY == 'django-insecure-dev-key' or SECRET_KEY.startswith('django-insecure-')):
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured(
        "CRITICAL SECURITY ERROR: Running in production with an insecure or default SECRET_KEY. "
        "Generate a strong random secret key and set it in your hosting environment."
    )

# Hosts configuration
allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
if allowed_hosts_env:
    ALLOWED_HOSTS = [h.strip() for h in allowed_hosts_env.split(',') if h.strip()]
elif DEBUG:
    ALLOWED_HOSTS = ['*']
else:
    ALLOWED_HOSTS = [
        'produitacademy.com',
        '.produitacademy.com',
        'api.produitacademy.com',
        'gate.produitacademy.com',
        'classes.produitacademy.com',
        'staff.produitacademy.com',
        'careers.produitacademy.com',
        'localhost',
        '127.0.0.1',
    ]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third Party
    'cloudinary_storage',
    'cloudinary',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    # Local
    'api',
    'gate',
    'staff_mgmt',
    'support',
    'careers',
    'classes_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'classes_app.middleware.ClearHSTSMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'produit_academy_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'produit_academy_backend.wsgi.application'

# --- DATABASE (NEON / RENDER) WITH CONNECTION POOLING ---
import sys
if 'test' in sys.argv:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }
else:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
            ssl_require=True
        )
    }
    if 'OPTIONS' not in DATABASES['default']:
        DATABASES['default']['OPTIONS'] = {}
    DATABASES['default']['OPTIONS']['connect_timeout'] = 10

# --- HIGH-PERFORMANCE IN-MEMORY CACHE ---
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'produit_classes_cache',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 5000,
        }
    }
}

AUTH_USER_MODEL = 'api.User'

# --- CORS & CSRF ---
# --- CORS & CSRF ---
PROD_ALLOWED_ORIGINS = [
    'https://produitacademy.com',
    'https://www.produitacademy.com',
    'https://classes.produitacademy.com',
    'https://gate.produitacademy.com',
    'https://staff.produitacademy.com',
    'https://careers.produitacademy.com',
]
DEV_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
    'http://localhost:3003',
    'http://localhost:3004',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3001',
    'http://127.0.0.1:3002',
    'http://127.0.0.1:3003',
    'http://127.0.0.1:3004',
]
DEFAULT_ALLOWED_ORIGINS = PROD_ALLOWED_ORIGINS + (DEV_ALLOWED_ORIGINS if DEBUG else [])

cors_env = os.environ.get('CORS_ALLOWED_ORIGINS')
if cors_env and cors_env.strip() != '*':
    parsed_origins = [o.strip() for o in cors_env.split(',') if o.strip()]
    CORS_ALLOWED_ORIGINS = list(set(parsed_origins + DEFAULT_ALLOWED_ORIGINS))
    CSRF_TRUSTED_ORIGINS = list(set(parsed_origins + DEFAULT_ALLOWED_ORIGINS))
    CORS_ALLOW_ALL_ORIGINS = False
elif DEBUG and cors_env == '*':
    # Permitted only in local debug development
    CORS_ALLOW_ALL_ORIGINS = True
    CSRF_TRUSTED_ORIGINS = []
else:
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS = DEFAULT_ALLOWED_ORIGINS
    CSRF_TRUSTED_ORIGINS = DEFAULT_ALLOWED_ORIGINS

CORS_ALLOW_CREDENTIALS = True

# --- REST FRAMEWORK ---
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'api.authentication.SingleSessionJWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'EXCEPTION_HANDLER': 'api.exceptions.custom_drf_exception_handler',
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/minute',
        'user': '1000/minute',
        'auth': '10/minute',
        'otp': '5/minute',
    }
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# --- PASSWORD VALIDATORS ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- SECURITY HEADERS ---
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False') == 'True'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True') == 'True'
    CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'True') == 'True'
    SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', '31536000'))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'True') == 'True'
    SECURE_HSTS_PRELOAD = os.environ.get('SECURE_HSTS_PRELOAD', 'True') == 'True'

# --- EMAIL SETTINGS ---
EMAIL_BACKEND = "anymail.backends.sendinblue.EmailBackend"
ANYMAIL = {
    "SENDINBLUE_API_KEY": os.environ.get('BREVO_API_KEY'),
}
DEFAULT_FROM_EMAIL = "Produit Academy <noreply@produitacademy.com>"
SERVER_EMAIL = "noreply@produitacademy.com"

# --- STATIC & MEDIA ---
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# --- CLOUDINARY CONFIGURATION ---
import cloudinary
CLOUDINARY_STORAGE = {
    'CLOUD_NAME': os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    'API_KEY': os.environ.get('CLOUDINARY_API_KEY', ''),
    'API_SECRET': os.environ.get('CLOUDINARY_API_SECRET', ''),
}
cloudinary.config(
    cloud_name=CLOUDINARY_STORAGE['CLOUD_NAME'],
    api_key=CLOUDINARY_STORAGE['API_KEY'],
    api_secret=CLOUDINARY_STORAGE['API_SECRET'],
    secure=True
)

DEFAULT_FILE_STORAGE = 'api.storage.CloudinaryMediaStorage'
STORAGES = {
    "default": {
        "BACKEND": "api.storage.CloudinaryMediaStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- TIMEZONE CONFIGURATION ---
TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True

# --- RAZORPAY & PAYMENT SETTINGS ---
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')
RAZORPAY_WEBHOOK_SECRET = os.environ.get('RAZORPAY_WEBHOOK_SECRET', '')
# Production safety: dummy payments are strictly disabled in production
ALLOW_DUMMY_PAYMENT = (os.environ.get('ALLOW_DUMMY_PAYMENT', 'False').strip().lower() == 'true') and DEBUG

# --- CHATBOT INTEGRATION (optional: endpoints stay disabled until both are set) ---
# CHATBOT_JWT_SECRET must equal SHARED_JWT_SECRET on the chatbot server.
# CHATBOT_SERVICE_KEY must equal MAIN_SITE_API_KEY on the chatbot server.
CHATBOT_JWT_SECRET = os.environ.get('CHATBOT_JWT_SECRET', '')
CHATBOT_SERVICE_KEY = os.environ.get('CHATBOT_SERVICE_KEY', '')

# --- LOGGING CONFIGURATION ---
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'api': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'classes_app': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'staff_mgmt': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'gate': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'support': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'careers': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

