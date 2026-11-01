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
# These are hard-coded here (NOT via os.environ) so they always override any
# .env values that point to Redis (which may not be running in dev/test).
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_STORE_EAGER_RESULT = True
