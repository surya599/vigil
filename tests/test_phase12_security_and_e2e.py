"""
Phase 12 Tests: Security Hardening, Credential Masking, Production Readiness,
Demo Data Seeding, and End-to-End NOC Lifecycle Verification.
"""
import importlib
from io import StringIO
from unittest.mock import patch
from django.test import TestCase
from django.urls import reverse
from django.core.management import call_command
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from devices.models import Device
from monitoring.models import NetworkInterface, InterfaceMetric
from monitoring.icmp import ICMPMonitoringEngine, ICMPChecker, ICMPResult
from monitoring.tasks import task_aggregate_traffic_snapshots, task_generate_daily_summaries
from analytics.models import NetworkTrafficSnapshot, DeviceDailySummary
from alerts.models import Alert, AlertThreshold
from topology.models import NetworkConnection
from topology.engine import TopologyEngine


User = get_user_model()


class SecurityAndCredentialMaskingTest(TestCase):
    """Verify SNMP secret masking, authentication guards, RBAC boundaries, and production security headers."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username="sec_admin",
            email="sec_admin@netpulse.local",
            password="StrongPassword!123",
        )
        self.admin.profile.role = "admin"
        self.admin.profile.save()

        self.viewer = User.objects.create_user(
            username="sec_viewer",
            email="sec_viewer@netpulse.local",
            password="StrongPassword!123",
        )
        self.viewer.profile.role = "viewer"
        self.viewer.profile.save()
        self.device = Device.objects.create(
            name="Core-Sec-Router",
            ip_address="10.250.1.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
            snmp_enabled=True,
            snmp_version=Device.SNMPVersion.V3,
            snmp_community="SuperSecretCommunityString99!",
            snmp_v3_user="snmp_sec_user",
            snmp_v3_auth_key="UltraSecretAuthPassphrase99!",
            snmp_v3_priv_key="UltraSecretPrivPassphrase99!",
        )

    def test_snmp_secrets_are_never_exposed_in_device_api_responses(self):
        """Ensure SNMPv2c community strings and SNMPv3 keys are write_only and omitted from API GET payloads."""
        api = APIClient()
        api.force_authenticate(user=self.admin)

        list_res = api.get("/api/devices/")
        self.assertEqual(list_res.status_code, 200)
        raw_list_body = list_res.content.decode("utf-8")
        self.assertNotIn("SuperSecretCommunityString99!", raw_list_body)
        self.assertNotIn("UltraSecretAuthPassphrase99!", raw_list_body)
        self.assertNotIn("UltraSecretPrivPassphrase99!", raw_list_body)

        detail_res = api.get(f"/api/devices/{self.device.id}/")
        self.assertEqual(detail_res.status_code, 200)
        payload = detail_res.json()
        self.assertNotIn("snmp_community", payload)
        self.assertNotIn("snmp_v3_auth_key", payload)
        self.assertNotIn("snmp_v3_priv_key", payload)

    def test_unauthenticated_access_blocked_across_html_and_api_routes(self):
        """Verify anonymous requests are redirected on HTML views and rejected (401/403) on REST API endpoints."""
        html_routes = [
            reverse("dashboard:overview"),
            reverse("devices:device-list"),
            reverse("topology:topology-view"),
            reverse("analytics:traffic-analytics"),
            reverse("monitoring:performance"),
            reverse("monitoring:history"),
            reverse("alerts:alert-list"),
            reverse("alerts:settings"),
        ]
        for url in html_routes:
            res = self.client.get(url)
            self.assertEqual(res.status_code, 302, f"Expected redirect for anonymous GET {url}")
            self.assertIn("/login/", res.url)

        api = APIClient()
        api_routes = [
            "/api/devices/",
            "/api/alerts/",
            "/api/alerts/summary/",
            "/api/alert-thresholds/",
            "/api/topology/connections/",
            "/api/topology/graph/",
            "/api/analytics/bandwidth-chart/",
            "/api/analytics/top-talkers/",
        ]
        for endpoint in api_routes:
            res = api.get(endpoint)
            self.assertIn(res.status_code, (401, 403), f"Expected 401/403 for anonymous GET {endpoint}")

    def test_viewer_rbac_cannot_mutate_devices_alerts_thresholds_or_topology(self):
        """Verify Viewer role is strictly read-only across all mutating endpoints."""
        api = APIClient()
        api.force_authenticate(user=self.viewer)

        # Cannot create or delete device
        res_dev = api.post(
            "/api/devices/",
            {"name": "Unauthorized-Router", "ip_address": "10.250.9.9", "device_type": "router"},
            format="json",
        )
        self.assertEqual(res_dev.status_code, 403)
        self.assertEqual(api.delete(f"/api/devices/{self.device.id}/").status_code, 403)

        # Cannot create alert threshold
        res_thresh = api.post(
            "/api/alert-thresholds/",
            {"name": "Unauth Profile", "high_latency_warning_ms": 99.0},
            format="json",
        )
        self.assertEqual(res_thresh.status_code, 403)

        # Cannot trigger topology auto-discovery
        res_disc = api.post("/api/topology/discover/")
        self.assertEqual(res_disc.status_code, 403)

    def test_production_settings_security_hardening(self):
        """Verify config.settings.production enforces strict security headers and cookies."""
        prod_settings = importlib.import_module("config.settings.production")
        self.assertFalse(prod_settings.DEBUG)
        self.assertEqual(prod_settings.X_FRAME_OPTIONS, "DENY")
        self.assertTrue(prod_settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertTrue(prod_settings.SESSION_COOKIE_SECURE)
        self.assertTrue(prod_settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(prod_settings.CSRF_COOKIE_SECURE)
        self.assertTrue(prod_settings.CSRF_COOKIE_HTTPONLY)
        self.assertGreaterEqual(prod_settings.SECURE_HSTS_SECONDS, 31536000)
        self.assertTrue(prod_settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)
        self.assertTrue(prod_settings.SECURE_HSTS_PRELOAD)

    def test_system_health_endpoint_returns_live_metrics(self):
        """Verify /api/health/ returns database status, monitored device count, and open incident count."""
        res = self.client.get(reverse("system-health"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["database"], "healthy")
        self.assertIn(data["version"], ("1.0.0", "2.0.0"))
        self.assertGreaterEqual(data["monitored_devices"], 1)
        self.assertIn("open_incidents", data)


class SeedNocDemoCommandTest(TestCase):
    """Verify the seed_noc_demo management command populates a complete NOC dataset idempotently."""

    def test_seed_noc_demo_command_is_idempotent(self):
        out1 = StringIO()
        call_command("seed_noc_demo", stdout=out1)
        self.assertTrue(
            "Successfully seeded VIGIL NOC demo dataset" in out1.getvalue()
            or "Successfully seeded NetPulse NOC demo dataset" in out1.getvalue()
        )

        device_count_1 = Device.objects.count()
        conn_count_1 = NetworkConnection.objects.count()
        alert_count_1 = Alert.objects.count()

        self.assertGreaterEqual(device_count_1, 7)
        self.assertGreaterEqual(conn_count_1, 6)
        self.assertGreaterEqual(alert_count_1, 2)
        self.assertGreaterEqual(NetworkTrafficSnapshot.objects.count(), 6)
        self.assertGreaterEqual(DeviceDailySummary.objects.count(), 7)

        # Run second time to verify idempotency (no duplicate devices or topology links)
        out2 = StringIO()
        call_command("seed_noc_demo", stdout=out2)
        self.assertEqual(Device.objects.count(), device_count_1)
        self.assertEqual(NetworkConnection.objects.count(), conn_count_1)
        self.assertEqual(Alert.objects.count(), alert_count_1)


class EndToEndNOCLifecycleTest(TestCase):
    """
    End-to-End Integration Test covering the full NetPulse NOC lifecycle:
    1. Device onboarding & threshold configuration
    2. Consecutive ICMP failures -> Offline status & DEVICE_OFFLINE alert creation -> Severity escalation
    3. Operator incident acknowledgement via REST API
    4. ICMP recovery ping -> Device returns ONLINE & alert auto-resolves
    5. Bandwidth telemetry -> 5-minute traffic snapshot & daily SLA summary rollup
    6. Automated Layer-3 subnet topology discovery
    """

    def setUp(self):
        self.operator = User.objects.create_user(
            username="e2e_operator",
            email="e2e_operator@netpulse.local",
            password="StrongPassword!123",
        )
        self.operator.profile.role = "operator"
        self.operator.profile.save()
        AlertThreshold.objects.create(
            name="E2E Global Thresholds",
            high_latency_warning_ms=100.0,
            high_latency_critical_ms=300.0,
            packet_loss_warning_pct=5.0,
            packet_loss_critical_pct=25.0,
            consecutive_failures_for_offline=2,
            is_active=True,
        )

    @patch.object(ICMPChecker, "ping_host")
    def test_full_noc_incident_recovery_analytics_and_topology_lifecycle(self, mock_ping):
        api = APIClient()
        api.force_authenticate(user=self.operator)
        engine = ICMPMonitoringEngine()

        # 1. Onboard two routers in the same /24 subnet via REST API
        r1_res = api.post(
            "/api/devices/",
            {
                "name": "E2E-Core-Router",
                "ip_address": "10.88.1.1",
                "device_type": "router",
                "location": "E2E Lab Rack 1",
                "monitoring_enabled": True,
                "polling_interval": 30,
            },
            format="json",
        )
        self.assertEqual(r1_res.status_code, 201)
        r1 = Device.objects.get(name="E2E-Core-Router")

        r2_res = api.post(
            "/api/devices/",
            {
                "name": "E2E-Dist-Switch",
                "ip_address": "10.88.1.2",
                "device_type": "switch",
                "location": "E2E Lab Rack 2",
                "monitoring_enabled": True,
                "polling_interval": 30,
            },
            format="json",
        )
        self.assertEqual(r2_res.status_code, 201)
        r2 = Device.objects.get(name="E2E-Dist-Switch")

        # 2. Simulate consecutive ICMP ping failures on r1 (threshold consecutive_failures_for_offline=2)
        mock_ping.return_value = ICMPResult(
            ip_address="10.88.1.1",
            packets_sent=3,
            packets_received=0,
            packet_loss=100.0,
            is_reachable=False,
        )
        engine.check_device(r1)  # Failure #1
        engine.check_device(r1)  # Failure #2 -> transitions to OFFLINE & triggers alert
        r1.refresh_from_db()
        self.assertEqual(r1.status, Device.Status.OFFLINE)

        offline_alert = Alert.objects.filter(
            device=r1,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            is_resolved=False,
        ).first()
        self.assertIsNotNone(offline_alert)
        self.assertEqual(offline_alert.severity, Alert.Severity.CRITICAL)

        # 3. Operator acknowledges the active incident via REST API
        ack_res = api.post(f"/api/alerts/{offline_alert.id}/acknowledge/")
        self.assertEqual(ack_res.status_code, 200)
        offline_alert.refresh_from_db()
        self.assertTrue(offline_alert.is_acknowledged)
        self.assertEqual(offline_alert.acknowledged_by, self.operator)

        # 4. Simulate ICMP recovery on r1 & healthy check on r2 -> auto-resolves alert
        mock_ping.return_value = ICMPResult(
            ip_address="10.88.1.1",
            packets_sent=3,
            packets_received=3,
            packet_loss=0.0,
            latencies=[4.0, 4.5, 5.0],
            min_latency=4.0,
            avg_latency=4.5,
            max_latency=5.0,
            jitter=0.5,
            is_reachable=True,
        )
        engine.check_device(r1)
        engine.check_device(r2)
        r1.refresh_from_db()
        r2.refresh_from_db()
        self.assertEqual(r1.status, Device.Status.ONLINE)
        self.assertEqual(r2.status, Device.Status.ONLINE)

        offline_alert.refresh_from_db()
        self.assertTrue(offline_alert.is_resolved)
        self.assertIsNotNone(offline_alert.resolved_at)

        # 5. Record interface bandwidth & run Celery aggregation and SLA summary tasks
        iface = NetworkInterface.objects.create(
            device=r1,
            interface_name="TenGigabitEthernet0/1",
            interface_index=1,
            speed_bps=10_000_000_000,
            operational_status=NetworkInterface.OperationalStatus.UP,
        )
        InterfaceMetric.objects.create(
            interface=iface,
            incoming_bytes=500_000_000,
            outgoing_bytes=300_000_000,
            incoming_bps=800_000_000.0,
            outgoing_bps=450_000_000.0,
        )

        snap_result = task_aggregate_traffic_snapshots()
        self.assertEqual(snap_result["status"], "success")
        latest_snap = NetworkTrafficSnapshot.objects.order_by("-recorded_at").first()
        self.assertIsNotNone(latest_snap)
        self.assertGreaterEqual(latest_snap.total_incoming_bps, 800_000_000.0)

        sla_result = task_generate_daily_summaries()
        self.assertEqual(sla_result["status"], "success")
        self.assertTrue(DeviceDailySummary.objects.filter(device=r1).exists())

        # 6. Run automated topology discovery and verify r1 <-> r2 link is created and active
        disc_result = TopologyEngine.auto_discover_subnet_links()
        self.assertGreaterEqual(disc_result["created"], 1)
        graph = TopologyEngine.build_topology_graph()
        self.assertEqual(graph["summary"]["total_nodes"], 2)
        self.assertEqual(graph["summary"]["active_edges"], 1)
