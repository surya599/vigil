from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DeviceListView,
    DeviceDetailView,
    DeviceCreateView,
    DeviceUpdateView,
    DeviceDeleteView,
    DevicePingView,
    DeviceViewSet,
)

app_name = "devices"

# REST API router with distinct basename to avoid colliding with template view names
router = DefaultRouter()
router.register(r"devices", DeviceViewSet, basename="device-api")

urlpatterns = [
    # Template views
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/add/", DeviceCreateView.as_view(), name="device-create"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("devices/<int:pk>/edit/", DeviceUpdateView.as_view(), name="device-edit"),
    path("devices/<int:pk>/delete/", DeviceDeleteView.as_view(), name="device-delete"),
    path("devices/<int:pk>/ping/", DevicePingView.as_view(), name="device-ping"),

    # REST API
    path("api/", include(router.urls)),
]
