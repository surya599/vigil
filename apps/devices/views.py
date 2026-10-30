from rest_framework import viewsets, permissions, filters
from .models import Device
from .serializers import DeviceSerializer


class DeviceViewSet(viewsets.ModelViewSet):
    """
    CRUD API endpoint for network devices.
    Supports filtering by status, device_type, and search by name/IP.
    """
    queryset = Device.objects.all().order_by("-updated_at")
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "ip_address", "mac_address", "location"]
    ordering_fields = ["name", "ip_address", "status", "updated_at", "last_checked"]

    def get_queryset(self):
        qs = super().get_queryset()
        status_param = self.request.query_params.get("status")
        device_type_param = self.request.query_params.get("device_type")
        monitoring_param = self.request.query_params.get("monitoring_enabled")

        if status_param:
            qs = qs.filter(status=status_param)
        if device_type_param:
            qs = qs.filter(device_type=device_type_param)
        if monitoring_param is not None:
            qs = qs.filter(monitoring_enabled=monitoring_param.lower() in ("true", "1"))
        return qs
