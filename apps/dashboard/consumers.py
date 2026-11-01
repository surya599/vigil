"""
NetPulse Real-Time WebSocket Consumers (Django Channels).

Provides:
1. NOCDashboardConsumer (/ws/noc/):
   Streams live network-wide status transitions, SNMP bandwidth updates,
   incident alert notifications, and periodic traffic snapshots to NOC operators.
2. DeviceDetailConsumer (/ws/devices/<device_id>/):
   Streams live per-device ICMP metrics, SNMP interface telemetry, and
   device-scoped alerts to operators viewing a specific device detail page.
"""

import logging
from datetime import timedelta

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.db.models import Avg, Sum
from django.utils import timezone

from alerts.models import Alert
from analytics.models import NetworkTrafficSnapshot
from dashboard.views import format_bandwidth
from devices.models import Device
from monitoring.broadcaster import NOC_DASHBOARD_GROUP
from monitoring.models import DeviceMetric, InterfaceMetric

logger = logging.getLogger("netpulse.dashboard.consumers")


class NOCDashboardConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer for the main NOC Overview Dashboard (/ws/noc/).
    Requires an authenticated user session.
    """

    group_name = NOC_DASHBOARD_GROUP

    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Send initial live NOC snapshot immediately upon connection
        snapshot_data = await self.get_noc_snapshot()
        await self.send_json({
            "type": "noc_snapshot",
            **snapshot_data,
        })

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        """
        Handles client-to-server WebSocket commands:
        - {"action": "ping"} -> {"type": "pong", "timestamp": ...}
        - {"action": "request_snapshot"} -> {"type": "noc_snapshot", ...}
        """
        action = content.get("action")
        if action == "ping":
            await self.send_json({
                "type": "pong",
                "timestamp": timezone.now().isoformat(),
            })
        elif action == "request_snapshot":
            snapshot_data = await self.get_noc_snapshot()
            await self.send_json({
                "type": "noc_snapshot",
                **snapshot_data,
            })
        else:
            await self.send_json({
                "type": "error",
                "message": f"Unsupported action: {action}",
            })

    # ── Channel Layer Group Event Handlers ───────────────────────────────

    async def device_status_update(self, event):
        """Forwards real-time ICMP check / status transition telemetry to client."""
        await self.send_json(event)

    async def snmp_telemetry_update(self, event):
        """Forwards real-time SNMP interface and bandwidth telemetry to client."""
        await self.send_json(event)

    async def alert_notification(self, event):
        """Forwards real-time incident alert creation/acknowledgement/resolution to client."""
        await self.send_json(event)

    async def traffic_snapshot_update(self, event):
        """Forwards aggregated network traffic snapshots to client."""
        await self.send_json(event)

    # ── Database Helpers ─────────────────────────────────────────────────

    @database_sync_to_async
    def get_noc_snapshot(self) -> dict:
        """Computes current NOC dashboard metrics from PostgreSQL."""
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

        return {
            "devices": {
                "total": Device.objects.count(),
                "online": Device.objects.filter(status=Device.Status.ONLINE).count(),
                "offline": Device.objects.filter(status=Device.Status.OFFLINE).count(),
                "warning": Device.objects.filter(status=Device.Status.WARNING).count(),
                "unknown": Device.objects.filter(status=Device.Status.UNKNOWN).count(),
            },
            "performance": {
                "avg_latency_ms": round(avg_latency, 2),
                "avg_packet_loss_pct": round(avg_packet_loss, 2),
                "global_uptime_pct": round(float(uptime_agg["v"] or 100.0), 2),
                "total_bandwidth_bps": round(total_bw_bps, 2),
                "total_bandwidth_display": format_bandwidth(total_bw_bps),
            },
            "alerts": {
                "active_total": active_alerts.count(),
                "critical": active_alerts.filter(severity=Alert.Severity.CRITICAL).count(),
                "warning": active_alerts.filter(severity=Alert.Severity.WARNING).count(),
            },
            "timestamp": timezone.now().isoformat(),
        }


class DeviceDetailConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer scoped to a single monitored device (/ws/devices/<device_id>/).
    Streams real-time ICMP ping results, SNMP interface updates, and device alerts.
    """

    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.device_id = int(self.scope["url_route"]["kwargs"]["device_id"])
        self.group_name = f"device_{self.device_id}"

        device_snapshot = await self.get_device_snapshot(self.device_id)
        if device_snapshot is None:
            await self.close(code=4404)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        await self.send_json({
            "type": "device_snapshot",
            **device_snapshot,
        })

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        action = content.get("action")
        if action == "ping":
            await self.send_json({
                "type": "pong",
                "device_id": self.device_id,
                "timestamp": timezone.now().isoformat(),
            })
        elif action == "request_snapshot":
            device_snapshot = await self.get_device_snapshot(self.device_id)
            if device_snapshot:
                await self.send_json({
                    "type": "device_snapshot",
                    **device_snapshot,
                })
        else:
            await self.send_json({
                "type": "error",
                "message": f"Unsupported action: {action}",
            })

    async def device_status_update(self, event):
        await self.send_json(event)

    async def snmp_telemetry_update(self, event):
        await self.send_json(event)

    async def alert_notification(self, event):
        await self.send_json(event)

    @database_sync_to_async
    def get_device_snapshot(self, device_id: int):
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return None

        latest = device.latest_metric
        return {
            "device_id": device.id,
            "device_name": device.name,
            "ip_address": device.ip_address,
            "status": device.status,
            "uptime_percentage": float(device.uptime_percentage),
            "consecutive_failures": device.consecutive_failures,
            "latency": latest.latency if latest else None,
            "packet_loss": latest.packet_loss if latest else 0.0,
            "jitter": latest.jitter if latest else None,
            "interfaces_count": device.interfaces.count(),
            "active_alerts_count": device.alerts.filter(is_resolved=False).count(),
            "timestamp": timezone.now().isoformat(),
        }
