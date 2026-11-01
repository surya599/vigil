"""
NetPulse Traffic Analytics & Historical Performance Views and REST APIs.

Provides:
1. TrafficAnalyticsView (/analytics/): Interactive bandwidth & interface utilization dashboard
2. bandwidth_chart_data (/api/analytics/bandwidth-chart/): Time-series Mbps (network-wide, per-device, or per-interface)
3. latency_chart_data (/api/analytics/latency-chart/): Time-series RTT latency, jitter, and packet loss
4. top_talkers_data (/api/analytics/top-talkers/): Top interfaces and devices ranked by throughput & link utilization
5. sla_summary_data (/api/analytics/sla-summary/): Historical SLA availability rollups from DeviceDailySummary
6. export_analytics_csv (/api/analytics/export-csv/): Downloadable CSV telemetry reports for traffic, latency, and SLA
"""

import csv
from datetime import timedelta
from typing import Optional

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Avg, Count, Max, Min, Sum
from django.http import HttpResponse
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework import permissions, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from devices.models import Device
from monitoring.models import DeviceMetric, InterfaceMetric, NetworkInterface
from .models import DeviceDailySummary, NetworkTrafficSnapshot
from .serializers import DeviceDailySummarySerializer, NetworkTrafficSnapshotSerializer


TIME_RANGE_MAP = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def parse_time_range(range_str: Optional[str]) -> Optional[timedelta]:
    """Converts a time range query parameter ('1h', '6h', '24h', '7d', '30d') into a timedelta."""
    if not range_str:
        return None
    return TIME_RANGE_MAP.get(range_str.lower().strip())


class TrafficAnalyticsView(LoginRequiredMixin, TemplateView):
    """
    Dedicated network traffic analytics dashboard.
    Visualizes bandwidth consumption, top talker interfaces, link utilization, and historical trends.
    """

    template_name = "analytics/traffic.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        devices = Device.objects.filter(monitoring_enabled=True).order_by("name")
        selected_device_id = self.request.GET.get("device", "")
        selected_range = self.request.GET.get("range", "24h")

        ifaces_qs = NetworkInterface.objects.select_related("device")
        if selected_device_id and selected_device_id.isdigit():
            ifaces_qs = ifaces_qs.filter(device_id=int(selected_device_id))

        recent_ifaces = list(ifaces_qs.order_by("-speed_bps", "interface_index")[:20])

        # Annotate each interface object in memory with latest Mbps and utilization %
        for iface in recent_ifaces:
            m = iface.latest_metric
            if m:
                in_bps = m.incoming_bps or 0.0
                out_bps = m.outgoing_bps or 0.0
                iface.current_in_mbps = round(in_bps / 1_000_000.0, 2)
                iface.current_out_mbps = round(out_bps / 1_000_000.0, 2)
                if iface.speed_bps and iface.speed_bps > 0:
                    util = (max(in_bps, out_bps) / float(iface.speed_bps)) * 100.0
                    iface.utilization_pct = round(min(100.0, util), 1)
                else:
                    iface.utilization_pct = 0.0
            else:
                iface.current_in_mbps = 0.0
                iface.current_out_mbps = 0.0
                iface.utilization_pct = 0.0

        ctx["devices"] = devices
        ctx["selected_device_id"] = int(selected_device_id) if selected_device_id.isdigit() else None
        ctx["selected_range"] = selected_range
        ctx["interfaces"] = recent_ifaces
        ctx["total_interfaces"] = ifaces_qs.count()
        ctx["active_interfaces"] = ifaces_qs.filter(
            operational_status=NetworkInterface.OperationalStatus.UP
        ).count()

        # Aggregate bandwidth & peak throughput
        latest_snapshot = NetworkTrafficSnapshot.objects.order_by("-recorded_at").first()
        if latest_snapshot:
            total_in = latest_snapshot.total_incoming_bps
            total_out = latest_snapshot.total_outgoing_bps
        else:
            total_in = sum((i.current_in_mbps * 1_000_000.0) for i in recent_ifaces)
            total_out = sum((i.current_out_mbps * 1_000_000.0) for i in recent_ifaces)

        peak_agg = NetworkTrafficSnapshot.objects.aggregate(
            max_in=Max("total_incoming_bps"),
            max_out=Max("total_outgoing_bps"),
        )
        peak_in_bps = peak_agg["max_in"] or total_in
        peak_out_bps = peak_agg["max_out"] or total_out

        ctx["current_incoming_mbps"] = round(total_in / 1_000_000.0, 2)
        ctx["current_outgoing_mbps"] = round(total_out / 1_000_000.0, 2)
        ctx["current_total_mbps"] = round((total_in + total_out) / 1_000_000.0, 2)
        ctx["peak_total_mbps"] = round((peak_in_bps + peak_out_bps) / 1_000_000.0, 2)
        return ctx


class NetworkTrafficSnapshotViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NetworkTrafficSnapshot.objects.all().order_by("-recorded_at")
    serializer_class = NetworkTrafficSnapshotSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        delta = parse_time_range(self.request.query_params.get("range"))
        if delta:
            qs = qs.filter(recorded_at__gte=timezone.now() - delta)
        limit = self.request.query_params.get("limit", 100)
        try:
            return qs[: int(limit)]
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
        days = self.request.query_params.get("days")
        if days and str(days).isdigit():
            cutoff_date = timezone.now().date() - timedelta(days=int(days))
            qs = qs.filter(date__gte=cutoff_date)
        return qs


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def bandwidth_chart_data(request):
    """
    Returns time-series bandwidth data for Chart.js.
    Supports:
    - ?range=1h|6h|24h|7d|30d
    - ?limit=30
    - ?interface_id=<id> (per-interface bandwidth history)
    - ?device_id=<id> (per-device interface bandwidth history)
    """
    try:
        limit = max(1, min(500, int(request.query_params.get("limit", 30))))
    except (ValueError, TypeError):
        limit = 30

    range_delta = parse_time_range(request.query_params.get("range"))
    cutoff = (timezone.now() - range_delta) if range_delta else None
    interface_id = request.query_params.get("interface_id")
    device_id = request.query_params.get("device_id")

    labels = []
    incoming_mbps = []
    outgoing_mbps = []

    if interface_id or device_id:
        if_qs = InterfaceMetric.objects.all()
        if interface_id and str(interface_id).isdigit():
            if_qs = if_qs.filter(interface_id=int(interface_id))
        elif device_id and str(device_id).isdigit():
            if_qs = if_qs.filter(interface__device_id=int(device_id))
        if cutoff:
            if_qs = if_qs.filter(recorded_at__gte=cutoff)

        recent_metrics = list(if_qs.order_by("-recorded_at")[:limit])
        recent_metrics.reverse()
        for m in recent_metrics:
            labels.append(timezone.localtime(m.recorded_at).strftime("%H:%M:%S"))
            incoming_mbps.append(round((m.incoming_bps or 0.0) / 1_000_000.0, 2))
            outgoing_mbps.append(round((m.outgoing_bps or 0.0) / 1_000_000.0, 2))
    else:
        snap_qs = NetworkTrafficSnapshot.objects.all()
        if cutoff:
            snap_qs = snap_qs.filter(recorded_at__gte=cutoff)
        snapshots = list(snap_qs.order_by("-recorded_at")[:limit])
        snapshots.reverse()

        for s in snapshots:
            labels.append(timezone.localtime(s.recorded_at).strftime("%H:%M:%S"))
            incoming_mbps.append(round((s.total_incoming_bps or 0.0) / 1_000_000.0, 2))
            outgoing_mbps.append(round((s.total_outgoing_bps or 0.0) / 1_000_000.0, 2))

        # Fallback to InterfaceMetric if no snapshots exist yet
        if not snapshots:
            if_qs = InterfaceMetric.objects.all()
            if cutoff:
                if_qs = if_qs.filter(recorded_at__gte=cutoff)
            recent_metrics = list(if_qs.order_by("-recorded_at")[:limit])
            recent_metrics.reverse()
            for m in recent_metrics:
                labels.append(timezone.localtime(m.recorded_at).strftime("%H:%M:%S"))
                incoming_mbps.append(round((m.incoming_bps or 0.0) / 1_000_000.0, 2))
                outgoing_mbps.append(round((m.outgoing_bps or 0.0) / 1_000_000.0, 2))

    current_in = incoming_mbps[-1] if incoming_mbps else 0.0
    current_out = outgoing_mbps[-1] if outgoing_mbps else 0.0
    peak_in = max(incoming_mbps) if incoming_mbps else 0.0
    peak_out = max(outgoing_mbps) if outgoing_mbps else 0.0
    avg_in = round(sum(incoming_mbps) / len(incoming_mbps), 2) if incoming_mbps else 0.0
    avg_out = round(sum(outgoing_mbps) / len(outgoing_mbps), 2) if outgoing_mbps else 0.0

    return Response({
        "labels": labels,
        "incoming_mbps": incoming_mbps,
        "outgoing_mbps": outgoing_mbps,
        "current_incoming_mbps": current_in,
        "current_outgoing_mbps": current_out,
        "current_total_mbps": round(current_in + current_out, 2),
        "peak_incoming_mbps": peak_in,
        "peak_outgoing_mbps": peak_out,
        "avg_incoming_mbps": avg_in,
        "avg_outgoing_mbps": avg_out,
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def latency_chart_data(request):
    """
    Returns network latency, jitter, and packet loss trends over time for Chart.js.
    Supports ?device_id=<id>, ?range=1h|6h|24h|7d|30d, and ?limit=30.
    """
    try:
        limit = max(1, min(500, int(request.query_params.get("limit", 30))))
    except (ValueError, TypeError):
        limit = 30

    device_id = request.query_params.get("device_id")
    range_delta = parse_time_range(request.query_params.get("range"))

    qs = DeviceMetric.objects.all()
    if device_id and str(device_id).isdigit():
        qs = qs.filter(device_id=int(device_id))
    if range_delta:
        qs = qs.filter(recorded_at__gte=timezone.now() - range_delta)

    recent_metrics = list(qs.order_by("-recorded_at")[:limit])
    recent_metrics.reverse()

    labels = []
    latency_vals = []
    packet_loss_vals = []
    jitter_vals = []

    for m in recent_metrics:
        labels.append(timezone.localtime(m.recorded_at).strftime("%H:%M:%S"))
        latency_vals.append(round(m.latency or 0.0, 1))
        packet_loss_vals.append(round(m.packet_loss or 0.0, 1))
        jitter_vals.append(round(m.jitter or 0.0, 2))

    non_zero_lat = [v for v in latency_vals if v > 0]
    summary = {
        "min_latency_ms": round(min(non_zero_lat), 1) if non_zero_lat else 0.0,
        "avg_latency_ms": round(sum(non_zero_lat) / len(non_zero_lat), 1) if non_zero_lat else 0.0,
        "max_latency_ms": round(max(non_zero_lat), 1) if non_zero_lat else 0.0,
        "avg_jitter_ms": round(sum(jitter_vals) / len(jitter_vals), 2) if jitter_vals else 0.0,
        "avg_packet_loss_pct": round(sum(packet_loss_vals) / len(packet_loss_vals), 2) if packet_loss_vals else 0.0,
        "samples_count": len(recent_metrics),
    }

    return Response({
        "labels": labels,
        "latency_ms": latency_vals,
        "packet_loss_pct": packet_loss_vals,
        "jitter_ms": jitter_vals,
        "summary": summary,
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def top_talkers_data(request):
    """
    Ranks network interfaces and devices by latest bandwidth consumption (Mbps)
    and calculates link utilization percentage against interface speed.
    """
    try:
        limit = max(1, min(50, int(request.query_params.get("limit", 10))))
    except (ValueError, TypeError):
        limit = 10

    interfaces = NetworkInterface.objects.select_related("device").all()
    iface_records = []
    device_totals = {}

    for iface in interfaces:
        m = iface.latest_metric
        in_bps = (m.incoming_bps or 0.0) if m else 0.0
        out_bps = (m.outgoing_bps or 0.0) if m else 0.0
        total_bps = in_bps + out_bps

        in_mbps = round(in_bps / 1_000_000.0, 2)
        out_mbps = round(out_bps / 1_000_000.0, 2)
        total_mbps = round(total_bps / 1_000_000.0, 2)

        if iface.speed_bps and iface.speed_bps > 0:
            utilization_pct = round(min(100.0, (max(in_bps, out_bps) / float(iface.speed_bps)) * 100.0), 1)
        else:
            utilization_pct = 0.0

        iface_records.append({
            "interface_id": iface.id,
            "interface_name": iface.interface_name,
            "device_id": iface.device_id,
            "device_name": iface.device.name,
            "label": f"{iface.device.name} · {iface.interface_name}",
            "operational_status": iface.operational_status,
            "speed_bps": iface.speed_bps,
            "incoming_mbps": in_mbps,
            "outgoing_mbps": out_mbps,
            "total_mbps": total_mbps,
            "utilization_pct": utilization_pct,
        })

        dev_entry = device_totals.setdefault(
            iface.device_id,
            {
                "device_id": iface.device_id,
                "device_name": iface.device.name,
                "ip_address": iface.device.ip_address,
                "incoming_bps": 0.0,
                "outgoing_bps": 0.0,
            },
        )
        dev_entry["incoming_bps"] += in_bps
        dev_entry["outgoing_bps"] += out_bps

    iface_records.sort(key=lambda x: x["total_mbps"], reverse=True)
    top_interfaces = iface_records[:limit]

    top_devices = []
    for d in device_totals.values():
        tot_bps = d["incoming_bps"] + d["outgoing_bps"]
        top_devices.append({
            "device_id": d["device_id"],
            "device_name": d["device_name"],
            "ip_address": d["ip_address"],
            "incoming_mbps": round(d["incoming_bps"] / 1_000_000.0, 2),
            "outgoing_mbps": round(d["outgoing_bps"] / 1_000_000.0, 2),
            "total_mbps": round(tot_bps / 1_000_000.0, 2),
        })
    top_devices.sort(key=lambda x: x["total_mbps"], reverse=True)

    return Response({
        "top_interfaces": top_interfaces,
        "top_devices": top_devices[:limit],
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def sla_summary_data(request):
    """
    Returns historical SLA & availability trends from DeviceDailySummary.
    Supports ?days=7|30 and ?device_id=<id>.
    """
    try:
        days = max(1, min(90, int(request.query_params.get("days", 7))))
    except (ValueError, TypeError):
        days = 7

    device_id = request.query_params.get("device_id")
    cutoff_date = timezone.now().date() - timedelta(days=days)

    qs = DeviceDailySummary.objects.select_related("device").filter(date__gte=cutoff_date)
    if device_id and str(device_id).isdigit():
        qs = qs.filter(device_id=int(device_id))

    summaries = list(qs.order_by("date"))

    # Group by date for Chart.js daily trend
    by_date = {}
    for s in summaries:
        d_str = s.date.strftime("%Y-%m-%d")
        bucket = by_date.setdefault(
            d_str,
            {"uptimes": [], "latencies": [], "alerts": 0},
        )
        bucket["uptimes"].append(float(s.uptime_percentage))
        bucket["latencies"].append(float(s.avg_latency or 0.0))
        bucket["alerts"] += int(s.total_alerts_count or 0)

    labels = list(by_date.keys())
    uptime_series = [
        round(sum(b["uptimes"]) / len(b["uptimes"]), 2) for b in by_date.values()
    ]
    latency_series = [
        round(sum(b["latencies"]) / len(b["latencies"]), 2) for b in by_date.values()
    ]
    alerts_series = [b["alerts"] for b in by_date.values()]

    if uptime_series:
        overall_sla = round(sum(uptime_series) / len(uptime_series), 2)
    else:
        # Fallback to live Device.uptime_percentage
        dev_qs = Device.objects.filter(monitoring_enabled=True)
        if device_id and str(device_id).isdigit():
            dev_qs = dev_qs.filter(id=int(device_id))
        agg = dev_qs.aggregate(v=Avg("uptime_percentage"))
        overall_sla = round(float(agg["v"] or 100.0), 2)

    sla_target = 99.9
    serializer = DeviceDailySummarySerializer(summaries, many=True)

    return Response({
        "labels": labels,
        "uptime_pct": uptime_series,
        "avg_latency_ms": latency_series,
        "alerts_count": alerts_series,
        "overall_sla_pct": overall_sla,
        "sla_target_pct": sla_target,
        "sla_compliant": overall_sla >= sla_target,
        "summaries": serializer.data,
    })


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def export_analytics_csv(request):
    """
    Exports historical network telemetry as a CSV file for NOC reporting.
    Query parameters:
    - ?type=traffic|latency|sla (default: traffic)
    - ?device_id=<id>
    - ?range=1h|6h|24h|7d|30d
    """
    report_type = request.query_params.get("type", "traffic").lower().strip()
    device_id = request.query_params.get("device_id")
    range_delta = parse_time_range(request.query_params.get("range", "24h"))
    cutoff = (timezone.now() - range_delta) if range_delta else None

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="netpulse_{report_type}_report.csv"'
    writer = csv.writer(response)

    if report_type == "latency":
        writer.writerow([
            "Timestamp",
            "Device Name",
            "IP Address",
            "Status",
            "Latency (ms)",
            "Jitter (ms)",
            "Packet Loss (%)",
        ])
        qs = DeviceMetric.objects.select_related("device").order_by("-recorded_at")
        if device_id and str(device_id).isdigit():
            qs = qs.filter(device_id=int(device_id))
        if cutoff:
            qs = qs.filter(recorded_at__gte=cutoff)
        for m in qs[:500]:
            writer.writerow([
                timezone.localtime(m.recorded_at).strftime("%Y-%m-%d %H:%M:%S"),
                m.device.name,
                m.device.ip_address,
                m.status,
                m.latency if m.latency is not None else "",
                m.jitter if m.jitter is not None else "",
                m.packet_loss,
            ])

    elif report_type == "sla":
        writer.writerow([
            "Date",
            "Device Name",
            "Uptime (%)",
            "Uptime (s)",
            "Downtime (s)",
            "Avg Latency (ms)",
            "Max Latency (ms)",
            "Avg Packet Loss (%)",
            "Alerts Count",
        ])
        qs = DeviceDailySummary.objects.select_related("device").order_by("-date")
        if device_id and str(device_id).isdigit():
            qs = qs.filter(device_id=int(device_id))
        for s in qs[:500]:
            writer.writerow([
                s.date.strftime("%Y-%m-%d"),
                s.device.name,
                float(s.uptime_percentage),
                s.uptime_seconds,
                s.downtime_seconds,
                s.avg_latency,
                s.max_latency,
                s.avg_packet_loss,
                s.total_alerts_count,
            ])

    else:
        # Default: traffic report
        writer.writerow([
            "Timestamp",
            "Total Devices",
            "Online Devices",
            "Offline Devices",
            "Warning Devices",
            "Avg Latency (ms)",
            "Avg Packet Loss (%)",
            "Incoming (Mbps)",
            "Outgoing (Mbps)",
            "Total Bandwidth (Mbps)",
        ])
        qs = NetworkTrafficSnapshot.objects.order_by("-recorded_at")
        if cutoff:
            qs = qs.filter(recorded_at__gte=cutoff)
        for s in qs[:500]:
            in_mbps = round((s.total_incoming_bps or 0.0) / 1_000_000.0, 2)
            out_mbps = round((s.total_outgoing_bps or 0.0) / 1_000_000.0, 2)
            writer.writerow([
                timezone.localtime(s.recorded_at).strftime("%Y-%m-%d %H:%M:%S"),
                s.total_devices,
                s.online_devices,
                s.offline_devices,
                s.warning_devices,
                s.average_latency,
                s.average_packet_loss,
                in_mbps,
                out_mbps,
                round(in_mbps + out_mbps, 2),
            ])

    return response


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
