from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DeviceListView,
    DeviceDetailView,
    DeviceCreateView,
    DeviceUpdateView,
    DeviceDeleteView,
    DevicePingView,
    DeviceSnmpPollView,
    DeviceViewSet,
)
from .discovery_views import (
    NetworkDiscoveryView,
    DiscoveredDeviceViewSet,
    NetworkChangeEventViewSet,
    discovery_interfaces_api,
    validate_cidr_api,
    start_discovery_scan_api,
    stop_discovery_scan_api,
    discovery_scan_status_api,
)

app_name = "devices"

# REST API router with distinct basename to avoid colliding with template view names
router = DefaultRouter()
router.register(r"devices", DeviceViewSet, basename="device-api")
router.register(r"discovery/devices", DiscoveredDeviceViewSet, basename="discovered-device-api")
router.register(r"discovery/events", NetworkChangeEventViewSet, basename="discovery-event-api")

urlpatterns = [
    # Template views
    path("discovery/", NetworkDiscoveryView.as_view(), name="discovery"),
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/add/", DeviceCreateView.as_view(), name="device-create"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("devices/<int:pk>/edit/", DeviceUpdateView.as_view(), name="device-edit"),
    path("devices/<int:pk>/delete/", DeviceDeleteView.as_view(), name="device-delete"),
    path("devices/<int:pk>/ping/", DevicePingView.as_view(), name="device-ping"),
    path("devices/<int:pk>/snmp-poll/", DeviceSnmpPollView.as_view(), name="device-snmp-poll"),

    # Discovery REST APIs
    path("api/discovery/interfaces/", discovery_interfaces_api, name="api-discovery-interfaces"),
    path("api/discovery/validate-cidr/", validate_cidr_api, name="api-discovery-validate-cidr"),
    path("api/discovery/scans/start/", start_discovery_scan_api, name="api-discovery-start"),
    path("api/discovery/scans/<int:pk>/stop/", stop_discovery_scan_api, name="api-discovery-stop"),
    path("api/discovery/scans/<int:pk>/status/", discovery_scan_status_api, name="api-discovery-status"),

    # REST API
    path("api/", include(router.urls)),
]
