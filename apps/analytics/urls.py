from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import (
    DeviceDailySummaryViewSet,
    NetworkTrafficSnapshotViewSet,
    TrafficAnalyticsView,
    bandwidth_chart_data,
    device_distribution_data,
    export_analytics_csv,
    latency_chart_data,
    sla_summary_data,
    top_talkers_data,
    traffic_overview,
)

app_name = "analytics"

router = DefaultRouter()
router.register(r"snapshots", NetworkTrafficSnapshotViewSet, basename="traffic-snapshot-api")
router.register(r"daily-summaries", DeviceDailySummaryViewSet, basename="device-daily-summary-api")

urlpatterns = [
    # UI View
    path("analytics/", TrafficAnalyticsView.as_view(), name="traffic-analytics"),

    # REST APIs for Chart.js, Top Talkers, SLA rollups & CSV Exports
    path("api/analytics/bandwidth-chart/", bandwidth_chart_data, name="bandwidth-chart"),
    path("api/analytics/latency-chart/", latency_chart_data, name="latency-chart"),
    path("api/analytics/top-talkers/", top_talkers_data, name="top-talkers"),
    path("api/analytics/sla-summary/", sla_summary_data, name="sla-summary"),
    path("api/analytics/export-csv/", export_analytics_csv, name="export-csv"),
    path("api/analytics/device-distribution/", device_distribution_data, name="device-distribution"),
    path("api/analytics/traffic/", traffic_overview, name="traffic-overview"),
    path("api/analytics/", include(router.urls)),
]
