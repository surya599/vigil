"""
URL configuration for NetPulse project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect
from django.http import JsonResponse
from dashboard.views import dashboard_stats


def health_check(request):
    from django.db import connection
    db_status = "healthy"
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"
    return JsonResponse({
        "status": "online",
        "service": "NetPulse Network Monitoring System",
        "version": "1.0.0",
        "database": db_status,
    })


urlpatterns = [
    # Root redirect to dashboard
    path("", lambda request: redirect("dashboard:overview"), name="root"),

    path("admin/", admin.site.urls),
    path("api/health/", health_check, name="system-health"),

    # Template-based application routes (namespaced)
    path("", include(("accounts.urls", "accounts"), namespace="accounts")),
    path("", include(("devices.urls", "devices"), namespace="devices")),
    path("dashboard/", include(("dashboard.urls", "dashboard"), namespace="dashboard")),

    # REST API endpoints
    path("api/dashboard/stats/", dashboard_stats, name="api-dashboard-stats"),
    path("api/monitoring/", include("monitoring.urls")),
    path("api/", include("alerts.urls")),
    path("api/analytics/", include("analytics.urls")),
    path("api/topology/", include("topology.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
