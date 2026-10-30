from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.utils import timezone
from django.db.models import Avg, Sum, Count
from datetime import timedelta

from rest_framework import viewsets, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from devices.models import Device
from monitoring.models import DeviceMetric, NetworkInterface, InterfaceMetric
from .models import NetworkTrafficSnapshot, DeviceDailySummary
from .serializers import NetworkTrafficSnapshotSerializer, DeviceDailySummarySerializer


class TrafficAnalyticsView(LoginRequiredMixin, TemplateView):
    """
    Dedicated network traffic analytics dashboard.
    Visualizes bandwidth consumption, interface rates, and protocol utilization.
    """
    template_name = "analytics/traffic.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # Top network interfaces by current traffic
        recent_ifaces = NetworkInterface.objects.select_related("device").order_by("-speed_bps")[:10]
        ctx["interfaces"] = recent_ifaces
        ctx["total_interfaces"] = NetworkInterface.objects.count()
        ctx["active_interfaces"] = NetworkInterface.objects.filter(operational_status=NetworkInterface.OperationalStatus.UP).count()

        # Aggregate bandwidth
        latest_snapshot = NetworkTrafficSnapshot.objects.order_by("-recorded_at").first()
        if latest_snapshot:
            total_in = latest_snapshot.total_incoming_bps
            total_out = latest_snapshot.total_outgoing_bps
        else:
            total_in = 0.0
            total_out = 0.0

        ctx["current_incoming_mbps"] = round(total_in / 1_000_000, 2)
        ctx["current_outgoing_mbps"] = round(total_out / 1_000_000, 2)
        ctx["current_total_mbps"] = round((total_in + total_out) / 1_000_000, 2)
        return ctx


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
def bandwidth_chart_data(request):
    """
    Returns time-series bandwidth data for Chart.js.
    Uses NetworkTrafficSnapshot or derives from InterfaceMetric.
    """
    limit = int(request.query_params.get("limit", 30))
    snapshots = list(NetworkTrafficSnapshot.objects.order_by("-recorded_at")[:limit])
    snapshots.reverse()

    labels = []
    incoming_mbps = []
    outgoing_mbps = []

    for s in snapshots:
        labels.append(s.recorded_at.strftime("%H:%M:%S"))
        incoming_mbps.append(round(s.total_incoming_bps / 1_000_000, 2))
        outgoing_mbps.append(round(s.total_outgoing_bps / 1_000_000, 2))

    # If no snapshots exist yet, provide recent interface metrics aggregated
    if not snapshots:
        # Check InterfaceMetric
        recent_metrics = InterfaceMetric.objects.order_by("-recorded_at")[:limit]
        for m in reversed(list(recent_metrics)):
            labels.append(m.recorded_at.strftime("%H:%M:%S"))
            incoming_mbps.append(round(m.incoming_bps / 1_000_000, 2))
            outgoing_mbps.append(round(m.outgoing_bps / 1_000_000, 2))

    current_in = incoming_mbps[-1] if incoming_mbps else 0.0
    current_out = outgoing_mbps[-1] if outgoing_mbps else 0.0

    return Response({
        "labels": labels,
        "incoming_mbps": incoming_mbps,
        "outgoing_mbps": outgoing_mbps,
        "current_incoming_mbps": current_in,
        "current_outgoing_mbps": current_out,
        "current_total_mbps": round(current_in + current_out, 2),
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def latency_chart_data(request):
    """
    Returns network latency and packet loss trends over time for Chart.js.
    """
    limit = int(request.query_params.get("limit", 30))
    device_id = request.query_params.get("device_id")

    qs = DeviceMetric.objects.all()
    if device_id:
        qs = qs.filter(device_id=device_id)
    
    recent_metrics = list(qs.order_by("-recorded_at")[:limit])
    recent_metrics.reverse()

    labels = []
    latency_vals = []
    packet_loss_vals = []

    for m in recent_metrics:
        labels.append(m.recorded_at.strftime("%H:%M:%S"))
        latency_vals.append(round(m.latency or 0.0, 1))
        packet_loss_vals.append(round(m.packet_loss or 0.0, 1))

    return Response({
        "labels": labels,
        "latency_ms": latency_vals,
        "packet_loss_pct": packet_loss_vals,
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def device_distribution_data(request):
    """
    Returns breakdown of devices by status and by device type for doughnut/bar charts.
    """
    status_counts = {
        "online": Device.objects.filter(status=Device.Status.ONLINE).count(),
        "warning": Device.objects.filter(status=Device.Status.WARNING).count(),
        "offline": Device.objects.filter(status=Device.Status.OFFLINE).count(),
        "unknown": Device.objects.filter(status=Device.Status.UNKNOWN).count(),
    }

    type_counts = {}
    for dt, label in Device.DeviceType.choices:
        type_counts[label] = Device.objects.filter(device_type=dt).count()

    return Response({
        "status_distribution": status_counts,
        "type_distribution": type_counts,
        "total": Device.objects.count(),
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def traffic_overview(request):
    """
    Provides aggregated traffic summary suitable for analytics charts.
    """
    limit = int(request.query_params.get("limit", 60))
    snapshots = NetworkTrafficSnapshot.objects.order_by("-recorded_at")[:limit]
    snapshots = list(reversed(snapshots))
    serializer = NetworkTrafficSnapshotSerializer(snapshots, many=True)
    return Response({
        "count": len(snapshots),
        "results": serializer.data,
    })
