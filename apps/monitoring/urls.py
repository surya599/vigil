from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PerformanceMonitoringView,
    MonitoringHistoryView,
    NetworkUtilitiesView,
    DeviceMetricViewSet,
    NetworkInterfaceViewSet,
    InterfaceMetricViewSet,
    dns_check_api,
    port_check_api,
    traceroute_api,
    uptime_report_api,
)

app_name = "monitoring"

router = DefaultRouter()
router.register(r"metrics", DeviceMetricViewSet, basename="device-metric-api")
router.register(r"interfaces", NetworkInterfaceViewSet, basename="network-interface-api")
router.register(r"interface-metrics", InterfaceMetricViewSet, basename="interface-metric-api")

urlpatterns = [
    # UI Views
    path("monitoring/performance/", PerformanceMonitoringView.as_view(), name="performance"),
    path("monitoring/history/", MonitoringHistoryView.as_view(), name="history"),
    path("monitoring/utilities/", NetworkUtilitiesView.as_view(), name="utilities"),

    # Network Utilities & SLA Reporting APIs
    path("api/monitoring/utilities/dns/", dns_check_api, name="utilities-dns-api"),
    path("api/monitoring/utilities/ports/", port_check_api, name="utilities-ports-api"),
    path("api/monitoring/utilities/traceroute/", traceroute_api, name="utilities-traceroute-api"),
    path("api/monitoring/utilities/uptime-report/", uptime_report_api, name="utilities-uptime-api"),

    # REST APIs (matching /api/monitoring/metrics/, etc.)
    path("api/monitoring/", include(router.urls)),
]
