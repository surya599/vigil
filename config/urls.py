"""
URL configuration for VIGIL – Network Intelligence Platform.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect
from django.http import JsonResponse
from dashboard.views import dashboard_stats

admin.site.site_header = "VIGIL Administration"
admin.site.site_title = "VIGIL Network Intelligence"
admin.site.index_title = "Intelligent Network Discovery, Monitoring and Analytics"


def health_check(request):
    from django.db import connection
    from devices.models import Device
    from alerts.models import Alert

    db_status = "healthy"
    device_count = 0
    active_alerts = 0
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        device_count = Device.objects.filter(monitoring_enabled=True).count()
        active_alerts = Alert.objects.filter(is_resolved=False).count()
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"
    return JsonResponse({
        "status": "online" if db_status == "healthy" else "degraded",
        "platform": "VIGIL",
        "category": "Network Intelligence Platform",
        "tagline": "See Everything. Miss Nothing.",
        "description": "Intelligent Network Discovery, Monitoring and Analytics.",
        "service": "VIGIL Network Intelligence Platform",
        "version": "2.0.0",
        "database": db_status,
        "monitored_devices": device_count,
        "open_incidents": active_alerts,
    })


urlpatterns = [
    # Root redirect to dashboard
    path("", lambda request: redirect("dashboard:overview"), name="root"),

    path("admin/", admin.site.urls),
    path("api/health/", health_check, name="system-health"),

    # Application routes (Template UI & REST APIs namespaced cleanly)
    path("", include(("accounts.urls", "accounts"), namespace="accounts")),
    path("", include(("devices.urls", "devices"), namespace="devices")),
    path("dashboard/", include(("dashboard.urls", "dashboard"), namespace="dashboard")),
    path("", include(("topology.urls", "topology"), namespace="topology")),
    path("", include(("analytics.urls", "analytics"), namespace="analytics")),
    path("", include(("monitoring.urls", "monitoring"), namespace="monitoring")),
    path("", include(("alerts.urls", "alerts"), namespace="alerts")),

    # Direct API route for dashboard stats
    path("api/dashboard/stats/", dashboard_stats, name="api-dashboard-stats"),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
