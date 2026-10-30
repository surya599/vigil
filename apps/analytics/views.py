from rest_framework import viewsets, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Avg
from devices.models import Device
from monitoring.models import DeviceMetric
from alerts.models import Alert
from .models import NetworkTrafficSnapshot, DeviceDailySummary
from .serializers import NetworkTrafficSnapshotSerializer, DeviceDailySummarySerializer


class NetworkTrafficSnapshotViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NetworkTrafficSnapshot.objects.all().order_by("-recorded_at")
    serializer_class = NetworkTrafficSnapshotSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        limit = self.request.query_params.get("limit", 100)
        try:
            return qs[:int(limit)]
        except (ValueError, TypeError):
            return qs[:100]


class DeviceDailySummaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DeviceDailySummary.objects.all().order_by("-date")
    serializer_class = DeviceDailySummarySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        device_id = self.request.query_params.get("device_id")
        if device_id:
            qs = qs.filter(device_id=device_id)
        return qs


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def traffic_overview(request):
    """
    Provides aggregated traffic summary suitable for analytics charts.
    Returns last N traffic snapshots in time-ascending order for Chart.js.
    """
    limit = int(request.query_params.get("limit", 60))
    snapshots = NetworkTrafficSnapshot.objects.order_by("-recorded_at")[:limit]
    snapshots = list(reversed(snapshots))
    serializer = NetworkTrafficSnapshotSerializer(snapshots, many=True)
    return Response({
        "count": len(snapshots),
        "results": serializer.data,
    })
