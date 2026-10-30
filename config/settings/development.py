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
