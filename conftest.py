"""
Root conftest.py – executed by pytest before any test collection.

Forcefully overrides Celery broker/backend env vars so that Celery never
attempts to connect to Redis (which is not running in this dev/test environment).
This must happen BEFORE Django settings or the Celery app are initialised.
"""

import os

# Override any .env-sourced Redis URLs for Celery so tests use the in-process
# memory transport and cache backend instead of requiring a live Redis server.
os.environ["CELERY_BROKER_URL"] = "memory://"
os.environ["CELERY_RESULT_BACKEND"] = "cache+memory://"
