from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DeviceMetricViewSet,
    NetworkInterfaceViewSet,
    InterfaceMetricViewSet,
)

router = DefaultRouter()
router.register(r"metrics", DeviceMetricViewSet, basename="device-metric")
router.register(r"interfaces", NetworkInterfaceViewSet, basename="network-interface")
router.register(r"interface-metrics", InterfaceMetricViewSet, basename="interface-metric")

urlpatterns = [
    path("", include(router.urls)),
]
