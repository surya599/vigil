"""
URL configuration for NetPulse project.
All API routes are namespaced under /api/
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse


def health_check(request):
    """Basic health check confirming system and live database connectivity."""
    from django.db import connection

    db_status = "healthy"
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    return JsonResponse(
        {
            "status": "online",
            "service": "NetPulse Network Monitoring System",
            "version": "1.0.0",
            "database": db_status,
        }
    )


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/health/", health_check, name="system-health"),

    # Accounts & Authentication
    path("api/accounts/", include("accounts.urls")),

    # Device Management
    path("api/", include("devices.urls")),

    # Monitoring Engine (metrics, interfaces)
    path("api/monitoring/", include("monitoring.urls")),

    # Alert Management
    path("api/", include("alerts.urls")),

    # Traffic & Performance Analytics
    path("api/analytics/", include("analytics.urls")),

    # Network Topology
    path("api/topology/", include("topology.urls")),

    # NOC Dashboard Aggregated Stats
    path("api/dashboard/", include("dashboard.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
