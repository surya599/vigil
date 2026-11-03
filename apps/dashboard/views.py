from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views import View
from django.db.models import Avg, Count, Q, Sum
from django.utils import timezone
from datetime import timedelta

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import permissions

from devices.models import Device, DiscoveredDevice, DiscoveryScan, NetworkChangeEvent
from monitoring.models import DeviceMetric, NetworkInterface, InterfaceMetric
from alerts.models import Alert
from analytics.models import NetworkTrafficSnapshot


def format_bandwidth(bps: float) -> str:
    """Helper to convert bits per second into human-readable string."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps:.0f} bps"


class DashboardOverviewView(LoginRequiredMixin, View):
    """
    Main NOC dashboard overview page.
    All statistics are dynamically computed from live database records.
    """
    template_name = "dashboard/overview.html"
    login_url = "accounts:login"

    def get(self, request):
        # Device summary counts
        total_devices = Device.objects.count()
        online_devices = Device.objects.filter(status=Device.Status.ONLINE).count()
        offline_devices = Device.objects.filter(status=Device.Status.OFFLINE).count()
        warning_devices = Device.objects.filter(status=Device.Status.WARNING).count()
        unknown_devices = Device.objects.filter(status=Device.Status.UNKNOWN).count()

        # Performance: rolling 5-minute window averages
        since = timezone.now() - timedelta(minutes=5)
        recent = DeviceMetric.objects.filter(
            recorded_at__gte=since,
            status=DeviceMetric.Status.ONLINE,
            latency__isnull=False,
        )
        avg_latency = recent.aggregate(v=Avg("latency"))["v"] or 0.0
        avg_packet_loss = recent.aggregate(v=Avg("packet_loss"))["v"] or 0.0

        # Global uptime
        uptime_agg = Device.objects.filter(
            monitoring_enabled=True
        ).aggregate(v=Avg("uptime_percentage"))
        global_uptime = uptime_agg["v"] or 100.0

        # Total Bandwidth Consumption
        latest_snapshot = NetworkTrafficSnapshot.objects.order_by("-recorded_at").first()
        if latest_snapshot:
            total_bw_bps = latest_snapshot.total_incoming_bps + latest_snapshot.total_outgoing_bps
        else:
            # Derive from latest InterfaceMetrics
            recent_iface_agg = InterfaceMetric.objects.filter(recorded_at__gte=since).aggregate(
                in_sum=Sum("incoming_bps"),
                out_sum=Sum("outgoing_bps"),
            )
            total_bw_bps = (recent_iface_agg["in_sum"] or 0.0) + (recent_iface_agg["out_sum"] or 0.0)

        total_bandwidth_display = format_bandwidth(total_bw_bps)

        # Active alerts
        active_alerts = Alert.objects.filter(is_resolved=False)
        critical_alerts = active_alerts.filter(severity=Alert.Severity.CRITICAL)[:5]
        recent_alerts = active_alerts.order_by("-created_at")[:10]

        # Recently updated devices
        recent_devices = Device.objects.order_by("-updated_at")[:10]

        # Discovery & Inventory Intelligence counts
        total_discovered = DiscoveredDevice.objects.count()
        unknown_discovered_count = DiscoveredDevice.objects.filter(
            trust_status=DiscoveredDevice.TrustStatus.UNKNOWN
        ).count()
        recent_network_events = NetworkChangeEvent.objects.select_related("discovered_device").order_by("-created_at")[:8]
        recent_scans = DiscoveryScan.objects.order_by("-started_at")[:5]

        # CPU & Memory averages across monitored devices
        res_agg = Device.objects.filter(monitoring_enabled=True).aggregate(
            avg_cpu=Avg("cpu_utilization"),
            avg_mem=Avg("memory_utilization"),
        )
        avg_cpu = round(res_agg["avg_cpu"] or 0.0, 1)
        avg_memory = round(res_agg["avg_mem"] or 0.0, 1)

        ctx = {
            "total_devices": total_devices,
            "total_discovered": total_discovered,
            "unknown_discovered_count": unknown_discovered_count,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "warning_devices": warning_devices,
            "unknown_devices": unknown_devices,
            "avg_latency": round(avg_latency, 1),
            "avg_packet_loss": round(avg_packet_loss, 2),
            "avg_cpu": avg_cpu,
            "avg_memory": avg_memory,
            "global_uptime": round(global_uptime, 2),
            "total_bandwidth_bps": total_bw_bps,
            "total_bandwidth_display": total_bandwidth_display,
            "active_alerts_count": active_alerts.count(),
            "critical_alerts_count": active_alerts.filter(severity=Alert.Severity.CRITICAL).count(),
            "critical_alerts": critical_alerts,
            "recent_alerts": recent_alerts,
            "recent_devices": recent_devices,
            "recent_network_events": recent_network_events,
            "recent_scans": recent_scans,
        }
        return render(request, self.template_name, ctx)


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def dashboard_stats(request):
    """
    REST API version of dashboard statistics — consumed by frontend JavaScript.
    All statistics are dynamically retrieved from the backend database.
    """
    since = timezone.now() - timedelta(minutes=5)
    recent = DeviceMetric.objects.filter(
        recorded_at__gte=since,
        status=DeviceMetric.Status.ONLINE,
        latency__isnull=False,
    )
    avg_latency = recent.aggregate(v=Avg("latency"))["v"] or 0.0
    avg_packet_loss = recent.aggregate(v=Avg("packet_loss"))["v"] or 0.0

    uptime_agg = Device.objects.filter(monitoring_enabled=True).aggregate(
        v=Avg("uptime_percentage")
    )

    # Bandwidth calculation
    latest_snapshot = NetworkTrafficSnapshot.objects.order_by("-recorded_at").first()
    if latest_snapshot:
        total_bw_bps = latest_snapshot.total_incoming_bps + latest_snapshot.total_outgoing_bps
    else:
        recent_iface_agg = InterfaceMetric.objects.filter(recorded_at__gte=since).aggregate(
            in_sum=Sum("incoming_bps"),
            out_sum=Sum("outgoing_bps"),
        )
        total_bw_bps = (recent_iface_agg["in_sum"] or 0.0) + (recent_iface_agg["out_sum"] or 0.0)

    active_alerts = Alert.objects.filter(is_resolved=False)

    res_agg = Device.objects.filter(monitoring_enabled=True).aggregate(
        avg_cpu=Avg("cpu_utilization"),
        avg_mem=Avg("memory_utilization"),
    )
    resource_devices = list(
        Device.objects.filter(monitoring_enabled=True)
        .order_by("name")[:10]
        .values("name", "cpu_utilization", "memory_utilization")
    )

    return Response({
        "devices": {
            "total": Device.objects.count(),
            "discovered_total": DiscoveredDevice.objects.count(),
            "unknown_inventory": DiscoveredDevice.objects.filter(
                trust_status=DiscoveredDevice.TrustStatus.UNKNOWN
            ).count(),
            "online": Device.objects.filter(status=Device.Status.ONLINE).count(),
            "offline": Device.objects.filter(status=Device.Status.OFFLINE).count(),
            "warning": Device.objects.filter(status=Device.Status.WARNING).count(),
            "unknown": Device.objects.filter(status=Device.Status.UNKNOWN).count(),
        },
        "performance": {
            "avg_latency_ms": round(avg_latency, 2),
            "avg_packet_loss_pct": round(avg_packet_loss, 2),
            "avg_cpu_pct": round(res_agg["avg_cpu"] or 0.0, 1),
            "avg_memory_pct": round(res_agg["avg_mem"] or 0.0, 1),
            "global_uptime_pct": round(uptime_agg["v"] or 100.0, 2),
            "total_bandwidth_bps": total_bw_bps,
            "total_bandwidth_display": format_bandwidth(total_bw_bps),
            "resource_devices": [
                {
                    "name": d["name"],
                    "cpu": round(d["cpu_utilization"] or 0.0, 1),
                    "memory": round(d["memory_utilization"] or 0.0, 1),
                }
                for d in resource_devices
            ],
        },
        "alerts": {
            "active_total": active_alerts.count(),
            "critical": active_alerts.filter(severity=Alert.Severity.CRITICAL).count(),
            "warning": active_alerts.filter(severity=Alert.Severity.WARNING).count(),
        },
        "meta": {
            "calculated_at": timezone.now().isoformat(),
            "metrics_window_minutes": 5,
        },
    })
