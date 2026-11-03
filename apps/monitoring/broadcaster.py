"""
NetPulse Real-Time WebSocket Broadcast Dispatcher.

Provides fault-tolerant helper functions to push live network events
(ICMP status transitions, SNMP interface telemetry, incident alerts, and
network traffic snapshots) to connected NOC operators over Django Channels.
"""

import logging
from typing import Optional

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone

logger = logging.getLogger("netpulse.monitoring.broadcaster")

NOC_DASHBOARD_GROUP = "noc_dashboard"


def _format_bandwidth(bps: float) -> str:
    """Converts bits per second into a human-readable NOC string."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps:.0f} bps"


def _send_group_event(group_name: str, message: dict) -> bool:
    """
    Safely dispatches an event dictionary to a Channels group from synchronous code.
    Returns True if dispatched, False if channel layer is unavailable or fails.
    """
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return False
        async_to_sync(channel_layer.group_send)(group_name, message)
        return True
    except Exception as exc:
        logger.debug("WebSocket broadcast to group '%s' skipped/failed: %s", group_name, exc)
        return False


def broadcast_device_metric(device, metric, old_status: Optional[str] = None) -> bool:
    """
    Broadcasts real-time ICMP check results and device status transitions
    to both the global NOC dashboard group and the device-specific group.
    """
    now_iso = (metric.recorded_at if getattr(metric, "recorded_at", None) else timezone.now()).isoformat()
    payload = {
        "type": "device_status_update",
        "device_id": device.id,
        "device_name": device.name,
        "ip_address": device.ip_address,
        "device_type": device.device_type,
        "old_status": old_status or device.status,
        "new_status": metric.status,
        "status_changed": (old_status is not None and old_status != metric.status),
        "latency": metric.latency,
        "packet_loss": metric.packet_loss,
        "jitter": metric.jitter,
        "consecutive_failures": device.consecutive_failures,
        "uptime_percentage": float(device.uptime_percentage),
        "timestamp": now_iso,
    }

    sent_noc = _send_group_event(NOC_DASHBOARD_GROUP, payload)
    _send_group_event(f"device_{device.id}", payload)
    return sent_noc


def broadcast_snmp_update(
    device,
    snmp_data,
    total_in_bps: float = 0.0,
    total_out_bps: float = 0.0,
) -> bool:
    """
    Broadcasts SNMP poll telemetry (interface counts, system uptime, aggregate device bps)
    to the global NOC dashboard group and the device-specific group.
    """
    interfaces_list = getattr(snmp_data, "interfaces", []) or []
    up_count = sum(1 for iface in interfaces_list if getattr(iface, "oper_status", "") == "up")
    down_count = sum(1 for iface in interfaces_list if getattr(iface, "oper_status", "") == "down")

    payload = {
        "type": "snmp_telemetry_update",
        "device_id": device.id,
        "device_name": device.name,
        "ip_address": device.ip_address,
        "is_successful": bool(getattr(snmp_data, "is_successful", False)),
        "sys_description": getattr(snmp_data, "sys_description", "") or "",
        "sys_uptime": getattr(snmp_data, "sys_uptime", "") or "",
        "interfaces_total": len(interfaces_list),
        "interfaces_up": up_count,
        "interfaces_down": down_count,
        "total_in_bps": round(total_in_bps, 2),
        "total_out_bps": round(total_out_bps, 2),
        "total_bandwidth_display": _format_bandwidth(total_in_bps + total_out_bps),
        "timestamp": timezone.now().isoformat(),
    }

    sent_noc = _send_group_event(NOC_DASHBOARD_GROUP, payload)
    _send_group_event(f"device_{device.id}", payload)
    return sent_noc


def broadcast_alert_event(alert, event: str = "created") -> bool:
    """
    Broadcasts incident alert lifecycle events ('created', 'acknowledged', 'resolved')
    to the global NOC dashboard group and the affected device group.
    """
    payload = {
        "type": "alert_notification",
        "event": event,
        "alert_id": alert.id,
        "device_id": alert.device_id,
        "device_name": alert.device.name if alert.device_id else "Unknown",
        "ip_address": alert.device.ip_address if alert.device_id else "",
        "alert_type": alert.alert_type,
        "alert_type_display": alert.get_alert_type_display(),
        "severity": alert.severity,
        "description": alert.description,
        "is_acknowledged": alert.is_acknowledged,
        "acknowledged_by": alert.acknowledged_by.username if alert.acknowledged_by else None,
        "is_resolved": alert.is_resolved,
        "timestamp": timezone.now().isoformat(),
    }

    sent_noc = _send_group_event(NOC_DASHBOARD_GROUP, payload)
    if alert.device_id:
        _send_group_event(f"device_{alert.device_id}", payload)
    return sent_noc


def broadcast_traffic_snapshot(snapshot) -> bool:
    """
    Broadcasts a newly aggregated NetworkTrafficSnapshot to all NOC dashboard clients
    for immediate Chart.js and stat card updates.
    """
    total_bw = (snapshot.total_incoming_bps or 0.0) + (snapshot.total_outgoing_bps or 0.0)
    recorded_at = snapshot.recorded_at or timezone.now()

    payload = {
        "type": "traffic_snapshot_update",
        "snapshot_id": snapshot.id,
        "total_devices": snapshot.total_devices,
        "online_devices": snapshot.online_devices,
        "offline_devices": snapshot.offline_devices,
        "warning_devices": snapshot.warning_devices,
        "average_latency": round(snapshot.average_latency or 0.0, 2),
        "average_packet_loss": round(snapshot.average_packet_loss or 0.0, 2),
        "total_incoming_bps": round(snapshot.total_incoming_bps or 0.0, 2),
        "total_outgoing_bps": round(snapshot.total_outgoing_bps or 0.0, 2),
        "incoming_mbps": round((snapshot.total_incoming_bps or 0.0) / 1_000_000.0, 2),
        "outgoing_mbps": round((snapshot.total_outgoing_bps or 0.0) / 1_000_000.0, 2),
        "total_bandwidth_display": _format_bandwidth(total_bw),
        "label": timezone.localtime(recorded_at).strftime("%H:%M:%S"),
        "timestamp": recorded_at.isoformat(),
    }

    return _send_group_event(NOC_DASHBOARD_GROUP, payload)


def broadcast_discovery_event(scan) -> bool:
    """
    Broadcasts network discovery scan completion/progress to all NOC dashboard clients.
    """
    payload = {
        "type": "discovery_scan_update",
        "scan_id": scan.id,
        "target_cidr": scan.target_cidr,
        "interface_name": scan.interface_name,
        "status": scan.status,
        "progress_pct": scan.progress_pct,
        "discovered_count": scan.discovered_count,
        "new_devices_count": scan.new_devices_count,
        "changes_detected_count": scan.changes_detected_count,
        "duration_seconds": scan.duration_seconds,
        "timestamp": timezone.now().isoformat(),
    }
    return _send_group_event(NOC_DASHBOARD_GROUP, payload)
