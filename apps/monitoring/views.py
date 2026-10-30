from rest_framework import viewsets, permissions, generics
from .models import DeviceMetric, NetworkInterface, InterfaceMetric
from .serializers import (
    DeviceMetricSerializer,
    NetworkInterfaceSerializer,
    InterfaceMetricSerializer,
)


class DeviceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only API for historical device latency & packet loss metrics.
    """
    queryset = DeviceMetric.objects.all().order_by("-recorded_at")
    serializer_class = DeviceMetricSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        device_id = self.request.query_params.get("device_id")
        if device_id:
            qs = qs.filter(device_id=device_id)
        limit = self.request.query_params.get("limit")
        if limit and limit.isdigit():
            qs = qs[:int(limit)]
        return qs


class NetworkInterfaceViewSet(viewsets.ModelViewSet):
    """
    API for managing device network interfaces.
    """
    queryset = NetworkInterface.objects.all().order_by("device", "interface_index")
    serializer_class = NetworkInterfaceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        device_id = self.request.query_params.get("device_id")
        if device_id:
            qs = qs.filter(device_id=device_id)
        return qs


class InterfaceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API for historical interface bandwidth metrics.
    """
    queryset = InterfaceMetric.objects.all().order_by("-recorded_at")
    serializer_class = InterfaceMetricSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        interface_id = self.request.query_params.get("interface_id")
        if interface_id:
            qs = qs.filter(interface_id=interface_id)
        return qs
