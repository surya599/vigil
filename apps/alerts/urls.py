from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AlertListView,
    SettingsView,
    AlertViewSet,
    AlertThresholdViewSet,
)

app_name = "alerts"

router = DefaultRouter()
router.register(r"alerts", AlertViewSet, basename="alert-api")
router.register(r"alert-thresholds", AlertThresholdViewSet, basename="alert-threshold-api")

urlpatterns = [
    # UI Views
    path("alerts/", AlertListView.as_view(), name="alert-list"),
    path("settings/", SettingsView.as_view(), name="settings"),

    # REST APIs (matching /api/alerts/ and /api/alerts/{id}/acknowledge/)
    path("api/", include(router.urls)),
]
