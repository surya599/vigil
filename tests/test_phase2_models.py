"""
Phase 2 automated tests: Django application models, relationships,
database constraints, and REST API endpoints.
"""
import pytest
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.utils import timezone

User = get_user_model()


# ─── Model Tests ───────────────────────────────────────────────────────────────


class UserProfileModelTest(TestCase):
    """Test UserProfile creation via signal and role logic."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testoperator",
            email="op@netpulse.local",
            password="SecurePass99!",
        )

    def test_profile_auto_created_on_user_create(self):
        from accounts.models import UserProfile
        self.assertTrue(hasattr(self.user, "profile"))
        self.assertIsNotNone(self.user.profile)

    def test_operator_role_default_for_non_superuser(self):
        from accounts.models import UserProfile
        self.assertEqual(self.user.profile.role, UserProfile.Role.OPERATOR)

    def test_superuser_gets_admin_role(self):
        from accounts.models import UserProfile
        admin = User.objects.create_superuser(
            username="superadmin", password="AdminPass99!", email="admin@netpulse.local"
        )
        self.assertEqual(admin.profile.role, UserProfile.Role.ADMINISTRATOR)

    def test_profile_is_admin_property(self):
        from accounts.models import UserProfile
        self.user.profile.role = UserProfile.Role.ADMINISTRATOR
        self.user.profile.save()
        self.assertTrue(self.user.profile.is_admin)

    def test_profile_str(self):
        self.assertIn("testoperator", str(self.user.profile))


class DeviceModelTest(TestCase):
    """Test Device model field validation, properties, and status transitions."""

    def setUp(self):
        from devices.models import Device
        self.device = Device.objects.create(
            name="Core-Router-01",
            ip_address="192.168.1.1",
            device_type=Device.DeviceType.ROUTER,
            location="Data Center Rack A-01",
        )

    def test_device_creation_with_defaults(self):
        from devices.models import Device
        self.assertEqual(self.device.status, Device.Status.UNKNOWN)
        self.assertTrue(self.device.monitoring_enabled)
        self.assertEqual(self.device.polling_interval, 30)
        self.assertEqual(self.device.consecutive_failures, 0)

    def test_device_str(self):
        self.assertIn("Core-Router-01", str(self.device))
        self.assertIn("192.168.1.1", str(self.device))

    def test_invalid_ip_address_rejected(self):
        from devices.models import Device
        device = Device(
            name="Bad-Device",
            ip_address="999.999.999.999",
            device_type=Device.DeviceType.ROUTER,
        )
        with self.assertRaises(Exception):
            device.full_clean()

    def test_duplicate_ip_rejected(self):
        from devices.models import Device
        from django.db import IntegrityError
        with self.assertRaises(Exception):
            Device.objects.create(
                name="Duplicate-Device",
                ip_address="192.168.1.1",
                device_type=Device.DeviceType.SWITCH,
            )

    def test_update_status_method(self):
        from devices.models import Device
        self.device.update_status(Device.Status.ONLINE)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, Device.Status.ONLINE)
        self.assertIsNotNone(self.device.last_checked)
        self.assertIsNotNone(self.device.last_status_change)

    def test_is_online_property(self):
        from devices.models import Device
        self.device.status = Device.Status.ONLINE
        self.assertTrue(self.device.is_online)

    def test_is_offline_property(self):
        from devices.models import Device
        self.device.status = Device.Status.OFFLINE
        self.assertTrue(self.device.is_offline)

    def test_device_unique_name(self):
        from devices.models import Device
        from django.db import IntegrityError
        with self.assertRaises(Exception):
            Device.objects.create(
                name="Core-Router-01",
                ip_address="10.10.10.1",
                device_type=Device.DeviceType.ROUTER,
            )


class DeviceMetricModelTest(TestCase):
    """Test DeviceMetric time-series recording and relationships."""

    def setUp(self):
        from devices.models import Device
        from monitoring.models import DeviceMetric
        self.device = Device.objects.create(
            name="Switch-01", ip_address="10.0.0.1"
        )
        self.metric = DeviceMetric.objects.create(
            device=self.device,
            status=DeviceMetric.Status.ONLINE,
            latency=12.5,
            packet_loss=0.0,
        )

    def test_metric_created_and_linked(self):
        from monitoring.models import DeviceMetric
        metrics = self.device.metrics.all()
        self.assertEqual(metrics.count(), 1)
        self.assertEqual(metrics.first().latency, 12.5)

    def test_metric_str_representation(self):
        self.assertIn("Switch-01", str(self.metric))
        self.assertIn("online", str(self.metric))

    def test_cascade_delete_with_device(self):
        from monitoring.models import DeviceMetric
        device_id = self.device.id
        self.device.delete()
        self.assertEqual(DeviceMetric.objects.filter(device_id=device_id).count(), 0)


class NetworkInterfaceModelTest(TestCase):
    """Test NetworkInterface uniqueness constraint and relationship."""

    def setUp(self):
        from devices.models import Device
        from monitoring.models import NetworkInterface
        self.device = Device.objects.create(
            name="Router-X1", ip_address="172.16.0.1"
        )
        self.iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="GigabitEthernet0/0",
            interface_index=1,
            speed_bps=1_000_000_000,
        )

    def test_interface_str(self):
        self.assertIn("Router-X1", str(self.iface))
        self.assertIn("GigabitEthernet0/0", str(self.iface))

    def test_duplicate_interface_rejected(self):
        from monitoring.models import NetworkInterface
        with self.assertRaises(Exception):
            NetworkInterface.objects.create(
                device=self.device,
                interface_name="GigabitEthernet0/0",
                interface_index=2,
            )

    def test_is_up_property(self):
        from monitoring.models import NetworkInterface
        self.iface.operational_status = NetworkInterface.OperationalStatus.UP
        self.assertTrue(self.iface.is_up)


class AlertModelTest(TestCase):
    """Test Alert creation, acknowledgement, resolution lifecycle."""

    def setUp(self):
        from devices.models import Device
        from alerts.models import Alert
        self.device = Device.objects.create(
            name="Firewall-01", ip_address="192.168.0.254"
        )
        self.user = User.objects.create_user(
            username="noc_op", password="Operator99!"
        )
        self.alert = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="Device failed 3 consecutive ICMP checks.",
        )

    def test_alert_defaults(self):
        self.assertFalse(self.alert.is_acknowledged)
        self.assertFalse(self.alert.is_resolved)
        self.assertIsNone(self.alert.acknowledged_by)

    def test_acknowledge_alert(self):
        self.alert.acknowledge(self.user)
        self.assertTrue(self.alert.is_acknowledged)
        self.assertEqual(self.alert.acknowledged_by, self.user)
        self.assertIsNotNone(self.alert.acknowledged_at)

    def test_resolve_alert(self):
        self.alert.resolve()
        self.assertTrue(self.alert.is_resolved)
        self.assertIsNotNone(self.alert.resolved_at)

    def test_alert_str(self):
        self.assertIn("CRITICAL", str(self.alert).upper())
        self.assertIn("Firewall-01", str(self.alert))


class NetworkConnectionModelTest(TestCase):
    """Test topology connections, self-loop prevention, and unique constraint."""

    def setUp(self):
        from devices.models import Device
        from topology.models import NetworkConnection
        self.router = Device.objects.create(
            name="Core-Router", ip_address="10.1.0.1",
            device_type="router"
        )
        self.switch = Device.objects.create(
            name="Access-Switch", ip_address="10.1.0.2",
            device_type="switch"
        )
        self.connection = NetworkConnection.objects.create(
            source_device=self.router,
            destination_device=self.switch,
            connection_type=NetworkConnection.ConnectionType.FIBER,
            link_speed="10 Gbps",
        )

    def test_connection_created(self):
        self.assertEqual(self.connection.source_device.name, "Core-Router")
        self.assertEqual(self.connection.destination_device.name, "Access-Switch")

    def test_connection_str_display(self):
        s = str(self.connection)
        self.assertIn("Core-Router", s)
        self.assertIn("Access-Switch", s)

    def test_self_loop_raises_validation_error(self):
        from topology.models import NetworkConnection
        conn = NetworkConnection(
            source_device=self.router,
            destination_device=self.router,
        )
        with self.assertRaises(ValidationError):
            conn.clean()


# ─── API Tests ─────────────────────────────────────────────────────────────────


class DashboardStatsAPITest(TestCase):
    """Test the live dashboard statistics API endpoint."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="api_tester", password="APIPass99!"
        )
        self.client.login(username="api_tester", password="APIPass99!")

    def test_dashboard_stats_returns_200(self):
        response = self.client.get("/api/dashboard/stats/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_stats_structure(self):
        response = self.client.get("/api/dashboard/stats/")
        data = response.json()
        self.assertIn("devices", data)
        self.assertIn("performance", data)
        self.assertIn("alerts", data)
        self.assertIn("meta", data)
        self.assertIn("total", data["devices"])
        self.assertIn("online", data["devices"])
        self.assertIn("offline", data["devices"])

    def test_dashboard_stats_requires_auth(self):
        self.client.logout()
        response = self.client.get("/api/dashboard/stats/")
        self.assertIn(response.status_code, [401, 403])


class DeviceAPITest(TestCase):
    """Test device CRUD API endpoints."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username="admin_test", password="Admin99!", email="admin@test.local"
        )
        self.client.login(username="admin_test", password="Admin99!")

    def test_create_device(self):
        payload = {
            "name": "Test-Switch-01",
            "ip_address": "10.10.0.1",
            "device_type": "switch",
            "location": "Server Room",
        }
        response = self.client.post(
            "/api/devices/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["name"], "Test-Switch-01")
        self.assertEqual(data["ip_address"], "10.10.0.1")

    def test_list_devices(self):
        from devices.models import Device
        Device.objects.create(name="Router-A", ip_address="192.168.10.1")
        response = self.client.get("/api/devices/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("results", data)
        self.assertGreaterEqual(data["count"], 1)

    def test_create_device_with_invalid_ip_rejected(self):
        payload = {
            "name": "Bad-Device",
            "ip_address": "300.400.500.600",
            "device_type": "router",
        }
        response = self.client.post(
            "/api/devices/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_delete_device(self):
        from devices.models import Device
        dev = Device.objects.create(name="Delete-Me", ip_address="10.99.0.1")
        response = self.client.delete(f"/api/devices/{dev.id}/")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Device.objects.filter(id=dev.id).exists())

    def test_unauthenticated_access_blocked(self):
        self.client.logout()
        response = self.client.get("/api/devices/")
        self.assertIn(response.status_code, [401, 403])


class AlertAPITest(TestCase):
    """Test Alert API listing and acknowledgement action."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="noc_agent", password="NOCPass99!"
        )
        self.client.login(username="noc_agent", password="NOCPass99!")

        from devices.models import Device
        from alerts.models import Alert
        self.device = Device.objects.create(
            name="Edge-Router", ip_address="203.0.113.1"
        )
        self.alert = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="Latency exceeded 150ms threshold.",
        )

    def test_list_alerts(self):
        response = self.client.get("/api/alerts/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["count"], 1)

    def test_acknowledge_alert_action(self):
        response = self.client.post(
            f"/api/alerts/{self.alert.id}/acknowledge/",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.alert.refresh_from_db()
        self.assertTrue(self.alert.is_acknowledged)
        self.assertEqual(self.alert.acknowledged_by, self.user)

    def test_double_acknowledge_returns_400(self):
        self.alert.acknowledge(self.user)
        response = self.client.post(
            f"/api/alerts/{self.alert.id}/acknowledge/",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
