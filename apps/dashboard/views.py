from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import permissions
from django.db.models import Avg, Count, Q
from django.utils import timezone
from datetime import timedelta

from devices.models import Device
from monitoring.models import DeviceMetric
from alerts.models import Alert


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def dashboard_stats(request):
    """
    Aggregated dashboard statistics - all values are dynamically computed
    from live database records. No hardcoded values.
    """
    total_devices = Device.objects.count()
    online_devices = Device.objects.filter(status=Device.Status.ONLINE).count()
    offline_devices = Device.objects.filter(status=Device.Status.OFFLINE).count()
    warning_devices = Device.objects.filter(status=Device.Status.WARNING).count()
    unknown_devices = Device.objects.filter(status=Device.Status.UNKNOWN).count()

    # Network-wide latency/packet-loss averages over the last 5 minutes
    since = timezone.now() - timedelta(minutes=5)
    recent_metrics = DeviceMetric.objects.filter(
        recorded_at__gte=since,
        status=DeviceMetric.Status.ONLINE,
        latency__isnull=False,
    )
    latency_agg = recent_metrics.aggregate(avg=Avg("latency"))
    packet_loss_agg = recent_metrics.aggregate(avg=Avg("packet_loss"))

    avg_latency = round(latency_agg["avg"] or 0.0, 2)
    avg_packet_loss = round(packet_loss_agg["avg"] or 0.0, 2)

    # Active (unresolved) alert counts by severity
    active_alerts = Alert.objects.filter(is_resolved=False)
    critical_alerts = active_alerts.filter(severity=Alert.Severity.CRITICAL).count()
    warning_alerts = active_alerts.filter(severity=Alert.Severity.WARNING).count()

    # Global uptime percentage (average across all devices)
    uptime_agg = Device.objects.filter(monitoring_enabled=True).aggregate(
        avg=Avg("uptime_percentage")
    )
    global_uptime = round(uptime_agg["avg"] or 100.0, 2)

    return Response({
        "devices": {
            "total": total_devices,
            "online": online_devices,
            "offline": offline_devices,
            "warning": warning_devices,
            "unknown": unknown_devices,
        },
        "performance": {
            "avg_latency_ms": avg_latency,
            "avg_packet_loss_pct": avg_packet_loss,
            "global_uptime_pct": global_uptime,
        },
        "alerts": {
            "active_total": active_alerts.count(),
            "critical": critical_alerts,
            "warning": warning_alerts,
        },
        "meta": {
            "calculated_at": timezone.now().isoformat(),
            "metrics_window_minutes": 5,
        },
    })
