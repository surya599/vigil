"""
Test suite for Phase 10: Incident Alert Generation & Acknowledgement Workflow.

Tests:
1. AlertEngine deduplication, severity escalation (WARNING -> CRITICAL), and auto-resolution
2. Bandwidth utilization threshold alerting (THRESHOLD_EXCEEDED trigger, escalation, recovery)
3. ICMP latency escalation integration (WARNING -> CRITICAL on RTT spike)
4. Mean Time To Acknowledge (MTTA) and Mean Time To Resolve (MTTR) KPI computation
5. REST API actions: /api/alerts/<id>/resolve/, /api/alerts/bulk-action/, /api/alerts/summary/,
   and RBAC enforcement (403 for Viewer role)
6. AlertListView UI filtering (device, alert_type, search query) and bulk POST actions
"""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import UserProfile
from alerts.engine import AlertEngine
from alerts.models import Alert
from devices.models import Device
from monitoring.icmp import ICMPChecker, ICMPMonitoringEngine, ICMPResult
from monitoring.models import NetworkInterface


class AlertEngineLifecycleTest(TestCase):
    """Tests AlertEngine deduplication, severity escalation, and bandwidth threshold evaluation."""

    def setUp(self):
        self.device = Device.objects.create(
            name="Alert-Engine-Router",
            ip_address="10.100.1.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
        )
        self.iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="TenGig0/1",
            interface_index=1,
            speed_bps=100_000_000,  # 100 Mbps
            operational_status="up",
        )

    def test_trigger_or_escalate_deduplicates_identical_active_alert(self):
        a1, created1 = AlertEngine.trigger_or_escalate_alert(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="RTT 140ms",
        )
        a2, created2 = AlertEngine.trigger_or_escalate_alert(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="RTT 145ms",
        )
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(a1.id, a2.id)
        self.assertEqual(Alert.objects.filter(device=self.device, is_resolved=False).count(), 1)

    def test_trigger_or_escalate_upgrades_warning_to_critical(self):
        alert, _ = AlertEngine.trigger_or_escalate_alert(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="RTT 140ms",
        )
        self.assertEqual(alert.severity, Alert.Severity.WARNING)

        escalated, changed = AlertEngine.trigger_or_escalate_alert(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.CRITICAL,
            description="RTT spiked to 420ms",
        )
        self.assertTrue(changed)
        self.assertEqual(escalated.id, alert.id)
        self.assertEqual(escalated.severity, Alert.Severity.CRITICAL)
        self.assertIn("420ms", escalated.description)
        self.assertEqual(Alert.objects.filter(device=self.device, is_resolved=False).count(), 1)

    def test_bandwidth_utilization_threshold_triggers_escalates_and_auto_resolves(self):
        # 1. 88 Mbps on 100 Mbps link (88% >= 85% warning threshold)
        alert = AlertEngine.evaluate_interface_bandwidth(
            device=self.device,
            interface=self.iface,
            in_bps=88_000_000.0,
            out_bps=20_000_000.0,
        )
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, Alert.AlertType.THRESHOLD_EXCEEDED)
        self.assertEqual(alert.severity, Alert.Severity.WARNING)

        # 2. 97 Mbps on 100 Mbps link (97% >= 95% critical threshold -> escalates)
        escalated = AlertEngine.evaluate_interface_bandwidth(
            device=self.device,
            interface=self.iface,
            in_bps=97_000_000.0,
            out_bps=30_000_000.0,
        )
        self.assertEqual(escalated.id, alert.id)
        self.assertEqual(escalated.severity, Alert.Severity.CRITICAL)

        # 3. Traffic drops to 40 Mbps (40% < 85% -> auto-resolves)
        res = AlertEngine.evaluate_interface_bandwidth(
            device=self.device,
            interface=self.iface,
            in_bps=40_000_000.0,
            out_bps=15_000_000.0,
        )
        self.assertIsNone(res)
        alert.refresh_from_db()
        self.assertTrue(alert.is_resolved)

    def test_icmp_latency_warning_escalates_to_critical_on_spike(self):
        warn_ping = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[150.0, 150.0, 150.0, 150.0],
            min_latency=150.0,
            avg_latency=150.0,
            max_latency=150.0,
            jitter=0.0,
            is_reachable=True,
        )
        crit_ping = ICMPResult(
            ip_address=self.device.ip_address,
            packets_sent=4,
            packets_received=4,
            packet_loss=0.0,
            latencies=[360.0, 360.0, 360.0, 360.0],
            min_latency=360.0,
            avg_latency=360.0,
            max_latency=360.0,
            jitter=0.0,
            is_reachable=True,
        )

        engine = ICMPMonitoringEngine()
        with patch.object(ICMPChecker, "ping_host", return_value=warn_ping):
            engine.check_device(self.device)

        active = Alert.objects.get(device=self.device, alert_type=Alert.AlertType.HIGH_LATENCY, is_resolved=False)
        self.assertEqual(active.severity, Alert.Severity.WARNING)

        with patch.object(ICMPChecker, "ping_host", return_value=crit_ping):
            engine.check_device(self.device)

        active.refresh_from_db()
        self.assertEqual(active.severity, Alert.Severity.CRITICAL)


class IncidentKPICalculationTest(TestCase):
    """Tests Mean Time To Acknowledge (MTTA) and Mean Time To Resolve (MTTR) computation."""

    def setUp(self):
        self.api_client = APIClient()
        self.user = User.objects.create_user(username="kpi_op", password="Password123!")
        self.api_client.force_authenticate(user=self.user)

        self.device = Device.objects.create(name="KPI-Switch", ip_address="10.100.2.1")
        now = timezone.now()

        # Alert 1: Created 60m ago, acknowledged 48m ago (12m to ack), resolved 30m ago (30m to resolve)
        a1 = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="Outage 1",
            created_at=now - timedelta(minutes=60),
            is_acknowledged=True,
            acknowledged_by=self.user,
            acknowledged_at=now - timedelta(minutes=48),
            is_resolved=True,
            resolved_at=now - timedelta(minutes=30),
        )
        # Alert 2: Created 20m ago, acknowledged 12m ago (8m to ack), still active
        a2 = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="Latency 2",
            created_at=now - timedelta(minutes=20),
            is_acknowledged=True,
            acknowledged_by=self.user,
            acknowledged_at=now - timedelta(minutes=12),
            is_resolved=False,
        )

    def test_compute_incident_kpis_and_summary_api_endpoint(self):
        res = self.api_client.get("/api/alerts/summary/")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        # Avg of 12m and 8m = 10.0m MTTA
        self.assertEqual(data["mtta_minutes"], 10.0)
        # 30.0m MTTR
        self.assertEqual(data["mttr_minutes"], 30.0)
        self.assertEqual(data["active_count"], 1)
        self.assertEqual(data["resolved_count"], 1)
        self.assertEqual(data["warning_count"], 1)


class AlertRESTWorkflowTest(TestCase):
    """Tests AlertViewSet resolve, bulk-action, and RBAC permissions."""

    def setUp(self):
        self.operator = User.objects.create_user(username="rest_op", password="Password123!")
        self.viewer = User.objects.create_user(username="rest_viewer", password="Password123!")
        self.viewer.profile.role = UserProfile.Role.VIEWER
        self.viewer.profile.save()

        self.device = Device.objects.create(name="REST-Firewall", ip_address="10.100.3.1")
        self.alert1 = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="Alert 1",
        )
        self.alert2 = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.PACKET_LOSS,
            severity=Alert.Severity.WARNING,
            description="Alert 2",
        )

    def test_operator_can_resolve_alert_via_api_and_double_resolve_returns_400(self):
        client = APIClient()
        client.force_authenticate(user=self.operator)

        res1 = client.post(f"/api/alerts/{self.alert1.id}/resolve/")
        self.assertEqual(res1.status_code, 200)
        self.alert1.refresh_from_db()
        self.assertTrue(self.alert1.is_resolved)

        res2 = client.post(f"/api/alerts/{self.alert1.id}/resolve/")
        self.assertEqual(res2.status_code, 400)

    def test_viewer_cannot_acknowledge_resolve_or_bulk_action_via_api(self):
        client = APIClient()
        client.force_authenticate(user=self.viewer)

        r_ack = client.post(f"/api/alerts/{self.alert1.id}/acknowledge/")
        self.assertEqual(r_ack.status_code, 403)

        r_res = client.post(f"/api/alerts/{self.alert1.id}/resolve/")
        self.assertEqual(r_res.status_code, 403)

        r_bulk = client.post("/api/alerts/bulk-action/", {"action": "acknowledge"}, format="json")
        self.assertEqual(r_bulk.status_code, 403)

    def test_bulk_action_api_acknowledges_and_resolves_multiple_alerts(self):
        client = APIClient()
        client.force_authenticate(user=self.operator)

        r_ack = client.post(
            "/api/alerts/bulk-action/",
            {"action": "acknowledge", "alert_ids": [self.alert1.id, self.alert2.id]},
            format="json",
        )
        self.assertEqual(r_ack.status_code, 200)
        self.assertEqual(r_ack.json()["processed_count"], 2)

        self.alert1.refresh_from_db()
        self.alert2.refresh_from_db()
        self.assertTrue(self.alert1.is_acknowledged)
        self.assertTrue(self.alert2.is_acknowledged)

        r_res = client.post(
            "/api/alerts/bulk-action/",
            {"action": "resolve"},
            format="json",
        )
        self.assertEqual(r_res.status_code, 200)
        self.assertEqual(r_res.json()["processed_count"], 2)
        self.alert1.refresh_from_db()
        self.assertTrue(self.alert1.is_resolved)


class AlertDashboardUIWorkflowTest(TestCase):
    """Tests AlertListView UI filters and bulk POST operations."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(username="ui_alert_op", password="Password123!")
        self.client.force_login(self.operator)

        self.dev1 = Device.objects.create(name="Branch-Router-Alpha", ip_address="10.100.4.1")
        self.dev2 = Device.objects.create(name="Core-Switch-Beta", ip_address="10.100.4.2")

        self.a1 = Alert.objects.create(
            device=self.dev1,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="WAN fiber link cut on Alpha",
        )
        self.a2 = Alert.objects.create(
            device=self.dev2,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            severity=Alert.Severity.WARNING,
            description="Elevated RTT on Beta",
        )

    def test_alert_list_filtering_by_device_and_search_query(self):
        res_dev = self.client.get(f"{reverse('alerts:alert-list')}?device={self.dev1.id}")
        self.assertEqual(res_dev.status_code, 200)
        self.assertContains(res_dev, "Branch-Router-Alpha")
        self.assertNotContains(res_dev, "Elevated RTT on Beta")

        res_q = self.client.get(f"{reverse('alerts:alert-list')}?q=fiber+link")
        self.assertEqual(res_q.status_code, 200)
        self.assertContains(res_q, "WAN fiber link cut on Alpha")
        self.assertNotContains(res_q, "Elevated RTT on Beta")

    def test_bulk_acknowledge_all_and_resolve_all_via_web_post(self):
        res_ack = self.client.post(reverse("alerts:alert-list"), {"action": "acknowledge_all"})
        self.assertEqual(res_ack.status_code, 302)
        self.assertEqual(Alert.objects.filter(is_acknowledged=True).count(), 2)

        res_resolve = self.client.post(reverse("alerts:alert-list"), {"action": "resolve_all"})
        self.assertEqual(res_resolve.status_code, 302)
        self.assertEqual(Alert.objects.filter(is_resolved=True).count(), 2)
