from django.apps import AppConfig


class MonitoringConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"
    verbose_name = "Network Monitoring Engine"

    def ready(self):
        # Register Celery tasks on Django initialization
        try:
            import monitoring.tasks  # noqa: F401
        except ImportError:
            pass
