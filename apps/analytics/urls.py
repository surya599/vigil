from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import NetworkTrafficSnapshotViewSet, DeviceDailySummaryViewSet, traffic_overview

router = DefaultRouter()
router.register(r"snapshots", NetworkTrafficSnapshotViewSet, basename="traffic-snapshot")
router.register(r"daily-summaries", DeviceDailySummaryViewSet, basename="device-daily-summary")

urlpatterns = [
    path("", include(router.urls)),
    path("traffic/", traffic_overview, name="traffic-overview"),
]
