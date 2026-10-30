from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TrafficAnalyticsView,
    NetworkTrafficSnapshotViewSet,
    DeviceDailySummaryViewSet,
    bandwidth_chart_data,
    latency_chart_data,
    device_distribution_data,
    traffic_overview,
)

app_name = "analytics"

router = DefaultRouter()
router.register(r"snapshots", NetworkTrafficSnapshotViewSet, basename="traffic-snapshot-api")
router.register(r"daily-summaries", DeviceDailySummaryViewSet, basename="device-daily-summary-api")

urlpatterns = [
    # UI View
    path("analytics/", TrafficAnalyticsView.as_view(), name="traffic-analytics"),

    # REST APIs for Chart.js & metrics
    path("api/analytics/bandwidth-chart/", bandwidth_chart_data, name="bandwidth-chart"),
    path("api/analytics/latency-chart/", latency_chart_data, name="latency-chart"),
    path("api/analytics/device-distribution/", device_distribution_data, name="device-distribution"),
    path("api/analytics/traffic/", traffic_overview, name="traffic-overview"),
    path("api/analytics/", include(router.urls)),
]
