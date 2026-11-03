from .base import *

# Development settings
DEBUG = True

# Allowed hosts in development
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"]

# Internal IPs for debug toolbar (if added later)
INTERNAL_IPS = ["127.0.0.1"]

# Channel layers - fallback to In-Memory for development if Redis is not running yet
# In Phase 8, Redis channel layer is enabled
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}

# Celery in Development:
# Force memory broker and cache+memory backend for dev and testing.
# Also update os.environ so Celery 5 does not prefer .env's CELERY_BROKER_URL /
# CELERY_RESULT_BACKEND over django.conf.settings when Redis is not running locally.
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"
os.environ["CELERY_BROKER_URL"] = CELERY_BROKER_URL
os.environ["CELERY_RESULT_BACKEND"] = CELERY_RESULT_BACKEND
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_STORE_EAGER_RESULT = True
