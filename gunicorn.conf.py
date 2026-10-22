# Picked up automatically by `gunicorn produit_academy_backend.wsgi` (any flags on the
# command line still win). The default is a single sync worker, so one slow request
# (email, Razorpay, Cloudinary) blocked every user. Threads let requests overlap while
# keeping one process, so the in-memory cache (sessions, OTP limits) stays consistent.
import os

workers = int(os.environ.get('GUNICORN_WORKERS', '1'))
worker_class = 'gthread'
threads = int(os.environ.get('GUNICORN_THREADS', '8'))
timeout = int(os.environ.get('GUNICORN_TIMEOUT', '120'))
graceful_timeout = 30
keepalive = 5
