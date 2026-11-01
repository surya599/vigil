"""
Test suite for Phase 8: Django Channels & WebSocket Real-Time Broadcast Engine.

Tests:
1. ASGI ProtocolTypeRouter, URLRouter, and Channel Layer configuration
2. NOCDashboardConsumer (/ws/noc/): authentication enforcement (4401), initial noc_snapshot,
   heartbeat ping/pong, on-demand request_snapshot, error handling
3. DeviceDetailConsumer (/ws/devices/<id>/): authentication enforcement (4401),
   missing device handling (4404), initial device_snapshot, ping/pong
4. End-to-end real-time broadcasts from ICMPMonitoringEngine, SNMPMonitoringEngine,
   Alert.acknowledge()/resolve(), and Celery task_aggregate_traffic_snapshots
5. Frontend template integration for noc_websocket.js and live WS indicators
"""

from unittest.mock import patch

from asgiref.sync import async_to_sync, sync_to_async
from channels.layers import get_channel_layer
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth.models import AnonymousUser, User
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from alerts.models import Alert
from config.asgi import application as asgi_application
from dashboard.routing import websocket_urlpatterns
from devices.models import Device
from monitoring.icmp import ICMPChecker, ICMPMonitoringEngine, ICMPResult
from monitoring.models import DeviceMetric, InterfaceMetric, NetworkInterface
from monitoring.snmp import SNMPClient, SNMPInterfaceData, SNMPMonitoringEngine, SNMPSystemData
from monitoring.tasks import task_aggregate_traffic_snapshots

# Build an inner ASGI router for direct WebsocketCommunicator testing with injected user scope
ws_router_app = URLRouter(websocket_urlpatterns)


class ASGIChannelsConfigTest(TestCase):
    """Verifies ASGI router, Channel Layer, and WebSocket URL patterns."""

    def test_asgi_application_is_protocol_type_router(self):
        self.assertIsInstance(asgi_application, ProtocolTypeRouter)
        self.assertIn("http", asgi_application.application_mapping)
        self.assertIn("websocket", asgi_application.application_mapping)

    def test_channel_layer_configured_and_functional(self):
        channel_layer = get_channel_layer()
        self.assertIsNotNone(channel_layer)

        async def _verify_send_receive():
            await channel_layer.group_add("test_group", "test_channel")
            await channel_layer.group_send("test_group", {"type": "test.event", "hello": "world"})
            msg = await channel_layer.receive("test_channel")
            await channel_layer.group_discard("test_group", "test_channel")
            return msg

        result = async_to_sync(_verify_send_receive)()
        self.assertEqual(result["hello"], "world")

    def test_websocket_routing_patterns_defined(self):
        self.assertEqual(len(websocket_urlpatterns), 2)
        routes = [str(p.pattern) for p in websocket_urlpatterns]
        self.assertIn("ws/noc/", routes)
        self.assertIn("ws/devices/<int:device_id>/", routes)


class NOCDashboardConsumerTest(TransactionTestCase):
    """Tests NOCDashboardConsumer (/ws/noc/) lifecycle and commands."""

    def setUp(self):
        self.user = User.objects.create_user(username="noc_ws_op", password="Password123!")
        self.device = Device.objects.create(
            name="WS-Core-Router",
            ip_address="10.240.1.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
            monitoring_enabled=True,
        )

    def test_unauthenticated_connection_rejected_with_4401(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            communicator.scope["user"] = AnonymousUser()
            connected, close_code = await communicator.connect()
            self.assertFalse(connected)
            self.assertEqual(close_code, 4401)
            await communicator.disconnect()

        async_to_sync(_run)()

    def test_authenticated_connection_accepted_and_receives_initial_snapshot(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            communicator.scope["user"] = self.user
            connected, _ = await communicator.connect()
            self.assertTrue(connected)

            msg = await communicator.receive_json_from()
            self.assertEqual(msg["type"], "noc_snapshot")
            self.assertEqual(msg["devices"]["total"], 1)
            self.assertEqual(msg["devices"]["online"], 1)
            self.assertIn("performance", msg)
            self.assertIn("alerts", msg)

            await communicator.disconnect()

        async_to_sync(_run)()

    def test_ping_command_returns_pong(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            communicator.scope["user"] = self.user
            connected, _ = await communicator.connect()
            self.assertTrue(connected)
            _ = await communicator.receive_json_from()  # initial noc_snapshot

            await communicator.send_json_to({"action": "ping"})
            reply = await communicator.receive_json_from()
            self.assertEqual(reply["type"], "pong")
            self.assertIn("timestamp", reply)

            await communicator.disconnect()

        async_to_sync(_run)()

    def test_request_snapshot_command_returns_updated_snapshot(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            communicator.scope["user"] = self.user
            await communicator.connect()
            initial = await communicator.receive_json_from()
            self.assertEqual(initial["devices"]["total"], 1)

            # Create a second device while connected
            await sync_to_async(Device.objects.create)(
                name="WS-Switch-2",
                ip_address="10.240.1.2",
                device_type=Device.DeviceType.SWITCH,
                status=Device.Status.OFFLINE,
            )

            await communicator.send_json_to({"action": "request_snapshot"})
            updated = await communicator.receive_json_from()
            self.assertEqual(updated["type"], "noc_snapshot")
            self.assertEqual(updated["devices"]["total"], 2)
            self.assertEqual(updated["devices"]["offline"], 1)

            await communicator.disconnect()

        async_to_sync(_run)()

    def test_unsupported_action_returns_error_message(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            communicator.scope["user"] = self.user
            await communicator.connect()
            _ = await communicator.receive_json_from()

            await communicator.send_json_to({"action": "unknown_command"})
            reply = await communicator.receive_json_from()
            self.assertEqual(reply["type"], "error")
            self.assertIn("unknown_command", reply["message"])

            await communicator.disconnect()

        async_to_sync(_run)()


class DeviceDetailConsumerTest(TransactionTestCase):
    """Tests DeviceDetailConsumer (/ws/devices/<device_id>/) lifecycle and commands."""

    def setUp(self):
        self.user = User.objects.create_user(username="dev_ws_op", password="Password123!")
        self.device = Device.objects.create(
            name="WS-Detail-Firewall",
            ip_address="10.240.2.1",
            device_type=Device.DeviceType.FIREWALL,
            status=Device.Status.ONLINE,
        )

    def test_unauthenticated_device_ws_rejected_with_4401(self):
        async def _run():
            communicator = WebsocketCommunicator(
                ws_router_app, f"/ws/devices/{self.device.id}/"
            )
            communicator.scope["user"] = AnonymousUser()
            connected, close_code = await communicator.connect()
            self.assertFalse(connected)
            self.assertEqual(close_code, 4401)
            await communicator.disconnect()

        async_to_sync(_run)()

    def test_nonexistent_device_ws_rejected_with_4404(self):
        async def _run():
            communicator = WebsocketCommunicator(ws_router_app, "/ws/devices/999999/")
            communicator.scope["user"] = self.user
            connected, close_code = await communicator.connect()
            self.assertFalse(connected)
            self.assertEqual(close_code, 4404)
            await communicator.disconnect()

        async_to_sync(_run)()

    def test_authenticated_device_ws_receives_device_snapshot_and_handles_ping(self):
        async def _run():
            communicator = WebsocketCommunicator(
                ws_router_app, f"/ws/devices/{self.device.id}/"
            )
            communicator.scope["user"] = self.user
            connected, _ = await communicator.connect()
            self.assertTrue(connected)

            snap = await communicator.receive_json_from()
            self.assertEqual(snap["type"], "device_snapshot")
            self.assertEqual(snap["device_id"], self.device.id)
            self.assertEqual(snap["device_name"], "WS-Detail-Firewall")

            await communicator.send_json_to({"action": "ping"})
            pong = await communicator.receive_json_from()
            self.assertEqual(pong["type"], "pong")
            self.assertEqual(pong["device_id"], self.device.id)

            await communicator.disconnect()

        async_to_sync(_run)()


class RealTimeBroadcastIntegrationTest(TransactionTestCase):
    """Tests live WebSocket broadcasts triggered by ICMP, SNMP, Alerts, and Celery tasks."""

    def setUp(self):
        self.user = User.objects.create_user(username="broadcast_op", password="Password123!")
        self.device = Device.objects.create(
            name="Broadcast-Edge-Router",
            ip_address="10.240.3.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
            snmp_enabled=True,
            monitoring_enabled=True,
        )

    def test_icmp_check_broadcasts_device_status_update_to_noc_and_device_ws(self):
        mock_ping = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[11.2, 12.0, 11.8, 12.2],
            min_latency=11.2,
            avg_latency=11.8,
            max_latency=12.2,
            jitter=0.47,
            is_reachable=True,
        )

        async def _run():
            noc_comm = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            noc_comm.scope["user"] = self.user
            await noc_comm.connect()
            _ = await noc_comm.receive_json_from()  # initial noc_snapshot

            dev_comm = WebsocketCommunicator(
                ws_router_app, f"/ws/devices/{self.device.id}/"
            )
            dev_comm.scope["user"] = self.user
            await dev_comm.connect()
            _ = await dev_comm.receive_json_from()  # initial device_snapshot

            def _exec_icmp():
                with patch.object(ICMPChecker, "ping_host", return_value=mock_ping):
                    engine = ICMPMonitoringEngine()
                    engine.check_device(self.device)

            await sync_to_async(_exec_icmp)()

            noc_event = await noc_comm.receive_json_from()
            self.assertEqual(noc_event["type"], "device_status_update")
            self.assertEqual(noc_event["device_id"], self.device.id)
            self.assertEqual(noc_event["new_status"], "online")
            self.assertEqual(noc_event["latency"], 11.8)

            dev_event = await dev_comm.receive_json_from()
            self.assertEqual(dev_event["type"], "device_status_update")
            self.assertEqual(dev_event["device_id"], self.device.id)

            await noc_comm.disconnect()
            await dev_comm.disconnect()

        async_to_sync(_run)()

    def test_icmp_failure_broadcasts_alert_created_and_recovery_broadcasts_resolved(self):
        offline_ping = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=0,
            packet_loss=100.0,
            is_reachable=False,
        )
        online_ping = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[10.0, 10.0, 10.0, 10.0],
            min_latency=10.0,
            avg_latency=10.0,
            max_latency=10.0,
            jitter=0.0,
            is_reachable=True,
        )

        # Pre-set consecutive_failures to 2 so next failure triggers OFFLINE & Alert
        self.device.consecutive_failures = 2
        self.device.save()

        async def _run():
            noc_comm = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            noc_comm.scope["user"] = self.user
            await noc_comm.connect()
            _ = await noc_comm.receive_json_from()

            def _trigger_offline():
                with patch.object(ICMPChecker, "ping_host", return_value=offline_ping):
                    ICMPMonitoringEngine().check_device(self.device)

            await sync_to_async(_trigger_offline)()

            # First broadcast is alert_notification (created), second is device_status_update
            msg1 = await noc_comm.receive_json_from()
            msg2 = await noc_comm.receive_json_from()
            self.assertEqual(msg1["type"], "alert_notification")
            self.assertEqual(msg1["event"], "created")
            self.assertEqual(msg1["alert_type"], Alert.AlertType.DEVICE_OFFLINE)
            self.assertEqual(msg2["type"], "device_status_update")
            self.assertEqual(msg2["new_status"], "offline")

            def _trigger_recovery():
                with patch.object(ICMPChecker, "ping_host", return_value=online_ping):
                    ICMPMonitoringEngine().check_device(self.device)

            await sync_to_async(_trigger_recovery)()

            msg3 = await noc_comm.receive_json_from()
            msg4 = await noc_comm.receive_json_from()
            self.assertEqual(msg3["type"], "alert_notification")
            self.assertEqual(msg3["event"], "resolved")
            self.assertTrue(msg3["is_resolved"])
            self.assertEqual(msg4["type"], "device_status_update")
            self.assertEqual(msg4["new_status"], "online")

            await noc_comm.disconnect()

        async_to_sync(_run)()

    def test_alert_acknowledge_broadcasts_acknowledged_event(self):
        alert = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="High RTT detected",
        )

        async def _run():
            noc_comm = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            noc_comm.scope["user"] = self.user
            await noc_comm.connect()
            _ = await noc_comm.receive_json_from()

            await sync_to_async(alert.acknowledge)(self.user)

            event = await noc_comm.receive_json_from()
            self.assertEqual(event["type"], "alert_notification")
            self.assertEqual(event["event"], "acknowledged")
            self.assertEqual(event["alert_id"], alert.id)
            self.assertEqual(event["acknowledged_by"], self.user.username)
            self.assertTrue(event["is_acknowledged"])

            await noc_comm.disconnect()

        async_to_sync(_run)()

    def test_snmp_poll_broadcasts_snmp_telemetry_update(self):
        mock_snmp_data = SNMPSystemData(
            sys_description="Cisco IOS XE Software",
            sys_uptime="45d 12h 10m",
            interfaces=[
                SNMPInterfaceData(
                    index=1,
                    name="GigabitEthernet0/0",
                    admin_status="up",
                    oper_status="up",
                    speed_bps=1_000_000_000,
                    in_octets=5_000_000,
                    out_octets=2_500_000,
                )
            ],
            is_successful=True,
        )

        async def _run():
            noc_comm = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            noc_comm.scope["user"] = self.user
            await noc_comm.connect()
            _ = await noc_comm.receive_json_from()

            def _exec_snmp():
                with patch.object(SNMPClient, "poll", return_value=mock_snmp_data):
                    SNMPMonitoringEngine().poll_device(self.device)

            await sync_to_async(_exec_snmp)()

            event = await noc_comm.receive_json_from()
            self.assertEqual(event["type"], "snmp_telemetry_update")
            self.assertEqual(event["device_id"], self.device.id)
            self.assertTrue(event["is_successful"])
            self.assertEqual(event["interfaces_total"], 1)
            self.assertEqual(event["interfaces_up"], 1)

            await noc_comm.disconnect()

        async_to_sync(_run)()

    def test_traffic_snapshot_task_broadcasts_traffic_snapshot_update(self):
        iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="eth0",
            interface_index=1,
            operational_status="up",
        )
        InterfaceMetric.objects.create(
            interface=iface,
            incoming_bytes=100000,
            outgoing_bytes=50000,
            incoming_bps=25_000_000.0,
            outgoing_bps=10_000_000.0,
        )

        async def _run():
            noc_comm = WebsocketCommunicator(ws_router_app, "/ws/noc/")
            noc_comm.scope["user"] = self.user
            await noc_comm.connect()
            _ = await noc_comm.receive_json_from()

            await sync_to_async(lambda: task_aggregate_traffic_snapshots.apply().get())()

            event = await noc_comm.receive_json_from()
            self.assertEqual(event["type"], "traffic_snapshot_update")
            self.assertEqual(event["incoming_mbps"], 25.0)
            self.assertEqual(event["outgoing_mbps"], 10.0)
            self.assertEqual(event["total_bandwidth_display"], "35.00 Mbps")

            await noc_comm.disconnect()

        async_to_sync(_run)()


class FrontendWebSocketIntegrationTest(TestCase):
    """Verifies that NOC templates include the WebSocket client script and DOM hooks."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="ui_ws_user", password="Password123!")
        self.client.force_login(self.user)
        self.device = Device.objects.create(
            name="UI-WS-Switch",
            ip_address="10.240.4.1",
            status=Device.Status.ONLINE,
        )

    def test_dashboard_renders_websocket_client_script_and_status_indicators(self):
        res = self.client.get(reverse("dashboard:overview"))
        self.assertEqual(res.status_code, 200)
        content = res.content.decode("utf-8")
        self.assertIn("js/noc_websocket.js", content)
        self.assertIn('id="ws-status-dot"', content)
        self.assertIn('id="ws-status-text"', content)
        self.assertIn(f'data-device-id="{self.device.id}"', content)
