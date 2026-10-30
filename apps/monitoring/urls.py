from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PerformanceMonitoringView,
    MonitoringHistoryView,
    DeviceMetricViewSet,
    NetworkInterfaceViewSet,
    InterfaceMetricViewSet,
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

    # REST APIs (matching /api/monitoring/metrics/, etc.)
    path("api/monitoring/", include(router.urls)),
]
