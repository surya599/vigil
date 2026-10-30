"""
Test suite for Phase 5: NetPulse ICMP Monitoring Engine.

Tests:
1. ICMPChecker ping calculations (loss %, min/avg/max latency, RFC 3550 jitter, reachability)
2. Fallback system ping parsing
3. ICMPMonitoringEngine state transitions (Online, Warning, Offline)
4. Consecutive failure tracking before marking offline
5. Alert generation and automated self-healing resolution on recovery
6. Thread-safe multi-device concurrent polling
7. On-demand ping REST API endpoint (/api/devices/<id>/ping/)
8. On-demand ping web view (/devices/<id>/ping/)
9. Management command (run_icmp_check)
"""

from unittest.mock import patch, MagicMock
from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.management import call_command
from io import StringIO

from devices.models import Device
from monitoring.models import DeviceMetric
from alerts.models import Alert, AlertThreshold
from monitoring.icmp import ICMPChecker, ICMPResult, ICMPMonitoringEngine


class ICMPCheckerUnitTest(TestCase):
    """Unit tests for low-level ICMP sampling and metric mathematics."""

    def test_icmp_checker_all_packets_received(self):
        checker = ICMPChecker(timeout=0.5)
        # Mock ping_once to return [10.0, 12.0, 14.0, 16.0]
        with patch.object(checker, "ping_once", side_effect=[10.0, 12.0, 14.0, 16.0]):
            res = checker.ping_host("192.168.1.1", count=4, interval=0)

        self.assertTrue(res.is_reachable)
        self.assertEqual(res.packets_sent, 4)
        self.assertEqual(res.packets_received, 4)
        self.assertEqual(res.packet_loss, 0.0)
        self.assertEqual(res.min_latency, 10.0)
        self.assertEqual(res.max_latency, 16.0)
        self.assertEqual(res.avg_latency, 13.0)
        # Jitter: (|12-10| + |14-12| + |16-14|) / 3 = (2 + 2 + 2) / 3 = 2.0
        self.assertEqual(res.jitter, 2.0)

    def test_icmp_checker_partial_packet_loss(self):
        checker = ICMPChecker(timeout=0.5)
        # 2 dropped, 2 received
        with patch.object(checker, "ping_once", side_effect=[20.0, None, 40.0, None]):
            res = checker.ping_host("192.168.1.2", count=4, interval=0)

        self.assertTrue(res.is_reachable)
        self.assertEqual(res.packets_sent, 4)
        self.assertEqual(res.packets_received, 2)
        self.assertEqual(res.packet_loss, 50.0)
        self.assertEqual(res.min_latency, 20.0)
        self.assertEqual(res.max_latency, 40.0)
        self.assertEqual(res.avg_latency, 30.0)
        # Jitter: |40 - 20| / 1 = 20.0
        self.assertEqual(res.jitter, 20.0)

    def test_icmp_checker_complete_packet_loss(self):
        checker = ICMPChecker(timeout=0.5)
        # All 4 dropped
        with patch.object(checker, "ping_once", side_effect=[None, None, None, None]):
            res = checker.ping_host("192.168.1.99", count=4, interval=0)

        self.assertFalse(res.is_reachable)
        self.assertEqual(res.packets_sent, 4)
        self.assertEqual(res.packets_received, 0)
        self.assertEqual(res.packet_loss, 100.0)
        self.assertIsNone(res.min_latency)
        self.assertIsNone(res.avg_latency)
        self.assertIsNone(res.max_latency)
        self.assertIsNone(res.jitter)

    def test_icmp_checker_system_ping_windows_parsing(self):
        checker = ICMPChecker()
        checker.system = "windows"
        mock_stdout = "Reply from 192.168.1.1: bytes=32 time=14ms TTL=64\n"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=mock_stdout, returncode=0)
            lat = checker.ping_once_system("192.168.1.1")
            self.assertEqual(lat, 14.0)

    def test_icmp_checker_system_ping_windows_sub_1ms_parsing(self):
        checker = ICMPChecker()
        checker.system = "windows"
        mock_stdout = "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128\n"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=mock_stdout, returncode=0)
            lat = checker.ping_once_system("127.0.0.1")
            self.assertGreaterEqual(lat, 0.1)

    def test_icmp_checker_system_ping_timeout_parsing(self):
        checker = ICMPChecker()
        mock_stdout = "Request timed out.\n"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=mock_stdout, returncode=1)
            lat = checker.ping_once_system("192.168.1.250")
            self.assertIsNone(lat)


class ICMPMonitoringEngineStateTransitionsTest(TestCase):
    """Tests device status transitions, consecutive failure thresholding, and alerting."""

    def setUp(self):
        AlertThreshold.objects.all().delete()
        self.threshold = AlertThreshold.objects.create(
            name="Test Thresholds",
            high_latency_warning_ms=100.0,
            high_latency_critical_ms=300.0,
            packet_loss_warning_pct=5.0,
            packet_loss_critical_pct=25.0,
            consecutive_failures_for_offline=3,
            is_active=True,
        )
        self.device = Device.objects.create(
            name="Core-Router-01",
            ip_address="10.0.0.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.UNKNOWN,
            consecutive_failures=0,
            monitoring_enabled=True,
        )
        self.engine = ICMPMonitoringEngine()

    def test_healthy_check_transitions_device_to_online(self):
        mock_result = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[12.0, 14.0, 13.0, 15.0],
            min_latency=12.0,
            avg_latency=13.5,
            max_latency=15.0,
            jitter=1.0,
            is_reachable=True,
        )
        with patch.object(self.engine.checker, "ping_host", return_value=mock_result):
            metric = self.engine.check_device(self.device)

        self.device.refresh_from_db()
        self.assertEqual(self.device.status, Device.Status.ONLINE)
        self.assertEqual(self.device.consecutive_failures, 0)
        self.assertIsNotNone(self.device.last_checked)
        self.assertEqual(metric.status, Device.Status.ONLINE)
        self.assertEqual(metric.latency, 13.5)
        self.assertEqual(metric.packet_loss, 0.0)

    def test_high_latency_transitions_to_warning_and_creates_alert(self):
        mock_result = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[150.0, 160.0, 155.0, 165.0],
            min_latency=150.0,
            avg_latency=157.5,  # Exceeds 100ms warning threshold
            max_latency=165.0,
            jitter=5.0,
            is_reachable=True,
        )
        with patch.object(self.engine.checker, "ping_host", return_value=mock_result):
            metric = self.engine.check_device(self.device)

        self.device.refresh_from_db()
        self.assertEqual(self.device.status, Device.Status.WARNING)
        self.assertEqual(metric.status, Device.Status.WARNING)

        # Alert should be created
        alert = Alert.objects.filter(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            is_resolved=False,
        ).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, Alert.Severity.WARNING)

    def test_consecutive_failures_reach_offline_threshold(self):
        mock_fail = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=0,
            packet_loss=100.0,
            is_reachable=False,
        )

        with patch.object(self.engine.checker, "ping_host", return_value=mock_fail):
            # Check 1: 1 failure -> Warning (flapping, not yet offline)
            self.engine.check_device(self.device)
            self.device.refresh_from_db()
            self.assertEqual(self.device.consecutive_failures, 1)
            self.assertEqual(self.device.status, Device.Status.WARNING)
            self.assertEqual(Alert.objects.filter(device=self.device, alert_type=Alert.AlertType.DEVICE_OFFLINE).count(), 0)

            # Check 2: 2 failures -> Warning
            self.engine.check_device(self.device)
            self.device.refresh_from_db()
            self.assertEqual(self.device.consecutive_failures, 2)
            self.assertEqual(self.device.status, Device.Status.WARNING)

            # Check 3: 3 failures -> Hits threshold of 3 -> Transitions to OFFLINE & triggers CRITICAL alert
            self.engine.check_device(self.device)
            self.device.refresh_from_db()
            self.assertEqual(self.device.consecutive_failures, 3)
            self.assertEqual(self.device.status, Device.Status.OFFLINE)

            offline_alert = Alert.objects.filter(
                device=self.device,
                alert_type=Alert.AlertType.DEVICE_OFFLINE,
                is_resolved=False,
            ).first()
            self.assertIsNotNone(offline_alert)
            self.assertEqual(offline_alert.severity, Alert.Severity.CRITICAL)

            # Check 4: 4 failures -> stays OFFLINE, does NOT create a duplicate alert
            self.engine.check_device(self.device)
            self.device.refresh_from_db()
            self.assertEqual(self.device.consecutive_failures, 4)
            self.assertEqual(self.device.status, Device.Status.OFFLINE)
            self.assertEqual(
                Alert.objects.filter(device=self.device, alert_type=Alert.AlertType.DEVICE_OFFLINE, is_resolved=False).count(),
                1,
            )

    def test_self_healing_recovery_resolves_offline_alert(self):
        # Set device to offline with 3 failures and an active alert
        self.device.status = Device.Status.OFFLINE
        self.device.consecutive_failures = 3
        self.device.save()

        alert = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="Host unreachable",
            is_resolved=False,
        )

        mock_online = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[5.0, 6.0, 5.5, 6.5],
            min_latency=5.0,
            avg_latency=5.75,
            max_latency=6.5,
            jitter=0.5,
            is_reachable=True,
        )

        with patch.object(self.engine.checker, "ping_host", return_value=mock_online):
            metric = self.engine.check_device(self.device)

        self.device.refresh_from_db()
        alert.refresh_from_db()

        self.assertEqual(self.device.status, Device.Status.ONLINE)
        self.assertEqual(self.device.consecutive_failures, 0)
        self.assertTrue(alert.is_resolved)
        self.assertIsNotNone(alert.resolved_at)


class ConcurrentMultiDevicePollingTest(TransactionTestCase):
    """Tests check_all_devices with concurrent execution."""

    def setUp(self):
        self.d1 = Device.objects.create(name="Dev-1", ip_address="10.1.0.1", monitoring_enabled=True)
        self.d2 = Device.objects.create(name="Dev-2", ip_address="10.1.0.2", monitoring_enabled=True)
        self.d3 = Device.objects.create(name="Dev-3", ip_address="10.1.0.3", monitoring_enabled=False)
        self.engine = ICMPMonitoringEngine()

    def test_check_all_devices_skips_disabled_devices(self):
        mock_online = ICMPResult(
            ip_address="test",
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            avg_latency=10.0,
            is_reachable=True,
        )
        with patch.object(self.engine.checker, "ping_host", return_value=mock_online):
            summary = self.engine.check_all_devices(max_workers=4, packet_count=2)

        # Only d1 and d2 had monitoring_enabled=True
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["online"], 2)
        self.assertEqual(summary["offline"], 0)
        self.assertEqual(summary["warning"], 0)
        self.assertEqual(len(summary["metrics"]), 2)


class OnDemandDevicePingAPITest(TestCase):
    """Tests POST /api/devices/<id>/ping/ endpoint."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="testoperator", password="securepassword123")
        self.user.profile.role = "operator"
        self.user.profile.save()
        self.device = Device.objects.create(
            name="Edge-Switch",
            ip_address="10.2.0.1",
            device_type=Device.DeviceType.SWITCH,
        )

    def test_ping_endpoint_requires_authentication(self):
        url = reverse("devices:device-api-ping", kwargs={"pk": self.device.pk})
        resp = self.client.post(url)
        self.assertIn(resp.status_code, [401, 403])

    def test_ping_endpoint_executes_and_returns_telemetry(self):
        self.client.login(username="testoperator", password="securepassword123")
        url = reverse("devices:device-api-ping", kwargs={"pk": self.device.pk})

        mock_res = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[8.0, 9.0, 8.5, 9.5],
            min_latency=8.0,
            avg_latency=8.75,
            max_latency=9.5,
            jitter=0.5,
            is_reachable=True,
        )

        with patch("monitoring.icmp.ICMPChecker.ping_host", return_value=mock_res):
            resp = self.client.post(url, {"count": 4, "timeout": 1.0}, content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["latency"], 8.75)
        self.assertEqual(data["packet_loss"], 0.0)
        self.assertEqual(data["jitter"], 0.5)
        self.assertEqual(data["consecutive_failures"], 0)


class OnDemandDevicePingViewTest(TestCase):
    """Tests POST /devices/<id>/ping/ web view."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(username="operator1", password="securepassword123")
        self.operator.profile.role = "operator"
        self.operator.profile.save()

        self.viewer = User.objects.create_user(username="viewer1", password="securepassword123")
        self.viewer.profile.role = "viewer"
        self.viewer.profile.save()

        self.device = Device.objects.create(
            name="Access-AP",
            ip_address="10.3.0.1",
            device_type=Device.DeviceType.ACCESS_POINT,
        )

    def test_viewer_cannot_trigger_ping(self):
        self.client.login(username="viewer1", password="securepassword123")
        url = reverse("devices:device-ping", kwargs={"pk": self.device.pk})
        resp = self.client.post(url)
        # OperatorRequiredMixin redirects or forbids non-operators
        self.assertEqual(resp.status_code, 302)

    def test_operator_can_trigger_ping_and_redirects_with_message(self):
        self.client.login(username="operator1", password="securepassword123")
        url = reverse("devices:device-ping", kwargs={"pk": self.device.pk})

        mock_res = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[2.0, 3.0, 2.5, 3.5],
            min_latency=2.0,
            avg_latency=2.75,
            max_latency=3.5,
            jitter=0.5,
            is_reachable=True,
        )

        with patch("monitoring.icmp.ICMPChecker.ping_host", return_value=mock_res):
            resp = self.client.post(url)

        self.assertEqual(resp.status_code, 302)
        self.assertRedirects(resp, reverse("devices:device-detail", kwargs={"pk": self.device.pk}))

    def test_operator_ajax_ping_returns_json(self):
        self.client.login(username="operator1", password="securepassword123")
        url = reverse("devices:device-ping", kwargs={"pk": self.device.pk})

        mock_res = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[4.0, 5.0, 4.5, 5.5],
            min_latency=4.0,
            avg_latency=4.75,
            max_latency=5.5,
            jitter=0.5,
            is_reachable=True,
        )

        with patch("monitoring.icmp.ICMPChecker.ping_host", return_value=mock_res):
            resp = self.client.post(url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["latency"], 4.75)


class RunICMPCheckManagementCommandTest(TestCase):
    """Tests the run_icmp_check management command."""

    def setUp(self):
        self.device = Device.objects.create(
            name="Command-Test-Host",
            ip_address="10.4.0.1",
            device_type=Device.DeviceType.SERVER,
            monitoring_enabled=True,
        )

    def test_run_icmp_check_single_device(self):
        mock_res = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=2,
            packets_received=2,
            packet_loss=0.0,
            avg_latency=15.0,
            is_reachable=True,
        )
        out = StringIO()
        with patch("monitoring.icmp.ICMPChecker.ping_host", return_value=mock_res):
            call_command("run_icmp_check", device_id=self.device.id, count=2, stdout=out)

        output = out.getvalue()
        self.assertIn("Command-Test-Host", output)
        self.assertIn("ONLINE", output)

    def test_run_icmp_check_all_devices(self):
        mock_res = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=2,
            packets_received=2,
            packet_loss=0.0,
            avg_latency=10.0,
            is_reachable=True,
        )
        out = StringIO()
        with patch("monitoring.icmp.ICMPChecker.ping_host", return_value=mock_res):
            call_command("run_icmp_check", count=2, stdout=out)

        output = out.getvalue()
        self.assertIn("Checked", output)
        self.assertIn("Online", output)
