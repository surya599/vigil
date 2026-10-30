"""
Phase 4 automated tests: NOC Dashboard overview, Chart.js telemetry APIs,
traffic analytics, performance monitoring, alert management, and topology view.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

from devices.models import Device
from monitoring.models import DeviceMetric, NetworkInterface, InterfaceMetric
from alerts.models import Alert, AlertThreshold
from analytics.models import NetworkTrafficSnapshot
from topology.models import NetworkConnection

User = get_user_model()


class DashboardFrontendViewTest(TestCase):
    """Test NOC Dashboard overview page rendering and live database metric aggregation."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="dash_user", password="UserPass99!")
        self.client.login(username="dash_user", password="UserPass99!")

        # Create sample devices with varied statuses
        self.dev1 = Device.objects.create(
            name="Router-Core-1",
            ip_address="192.168.1.1",
            device_type="router",
            status=Device.Status.ONLINE,
            uptime_percentage=99.95,
        )
        self.dev2 = Device.objects.create(
            name="Switch-Edge-1",
            ip_address="192.168.1.2",
            device_type="switch",
            status=Device.Status.WARNING,
            uptime_percentage=98.50,
        )
        self.dev3 = Device.objects.create(
            name="Server-Web-1",
            ip_address="192.168.1.10",
            device_type="server",
            status=Device.Status.OFFLINE,
            uptime_percentage=95.00,
        )

        # Create recent metrics
        DeviceMetric.objects.create(
            device=self.dev1,
            status=DeviceMetric.Status.ONLINE,
            latency=15.2,
            packet_loss=0.0,
        )
        DeviceMetric.objects.create(
            device=self.dev2,
            status=DeviceMetric.Status.WARNING,
            latency=145.0,
            packet_loss=4.5,
        )

        # Create sample snapshot for bandwidth
        NetworkTrafficSnapshot.objects.create(
            total_incoming_bps=12_500_000,
            total_outgoing_bps=8_200_000,
            online_devices=2,
            total_devices=3,
        )

    def test_overview_page_loads_200(self):
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/overview.html")

    def test_overview_context_contains_all_seven_metrics(self):
        response = self.client.get("/dashboard/")
        ctx = response.context
        self.assertEqual(ctx["total_devices"], 3)
        self.assertEqual(ctx["online_devices"], 1)
        self.assertEqual(ctx["warning_devices"], 1)
        self.assertEqual(ctx["offline_devices"], 1)
        self.assertIn("avg_latency", ctx)
        self.assertIn("avg_packet_loss", ctx)
        self.assertIn("global_uptime", ctx)
        self.assertIn("total_bandwidth_display", ctx)
        self.assertIn("Mbps", ctx["total_bandwidth_display"])

    def test_dashboard_stats_api_returns_live_bandwidth(self):
        response = self.client.get("/api/dashboard/stats/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_bandwidth_bps", data["performance"])
        self.assertIn("total_bandwidth_display", data["performance"])
        self.assertGreater(data["performance"]["total_bandwidth_bps"], 0)


class TrafficAnalyticsViewTest(TestCase):
    """Test Traffic Analytics view and Chart.js bandwidth telemetry endpoints."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="traffic_user", password="UserPass99!")
        self.client.login(username="traffic_user", password="UserPass99!")

        dev = Device.objects.create(name="Agg-Switch", ip_address="10.0.1.1")
        iface = NetworkInterface.objects.create(
            device=dev,
            interface_name="TenGig0/1",
            interface_index=1,
            speed_bps=10_000_000_000,
            operational_status="up",
        )
        InterfaceMetric.objects.create(
            interface=iface,
            incoming_bps=25_000_000,
            outgoing_bps=18_000_000,
        )

    def test_traffic_analytics_page_renders_200(self):
        response = self.client.get("/analytics/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analytics/traffic.html")

    def test_bandwidth_chart_api_returns_timeseries(self):
        response = self.client.get("/api/analytics/bandwidth-chart/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("labels", data)
        self.assertIn("incoming_mbps", data)
        self.assertIn("outgoing_mbps", data)
        self.assertIn("current_total_mbps", data)

    def test_latency_chart_api_returns_data(self):
        response = self.client.get("/api/analytics/latency-chart/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("labels", data)
        self.assertIn("latency_ms", data)
        self.assertIn("packet_loss_pct", data)

    def test_device_distribution_api(self):
        response = self.client.get("/api/analytics/device-distribution/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status_distribution", data)
        self.assertIn("type_distribution", data)
        self.assertIn("total", data)


class PerformanceAndHistoryViewsTest(TestCase):
    """Test Performance Monitoring and Monitoring History views."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="perf_user", password="UserPass99!")
        self.client.login(username="perf_user", password="UserPass99!")

        self.dev = Device.objects.create(name="Edge-Router", ip_address="172.16.1.1")
        DeviceMetric.objects.create(
            device=self.dev,
            status="online",
            latency=18.5,
            packet_loss=0.0,
            jitter=1.2,
        )

    def test_performance_view_renders_200(self):
        response = self.client.get("/monitoring/performance/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monitoring/performance.html")
        self.assertIn("selected_device", response.context)

    def test_monitoring_history_renders_200(self):
        response = self.client.get("/monitoring/history/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monitoring/history.html")
        self.assertContains(response, "Edge-Router")

    def test_history_filtering_by_status(self):
        response = self.client.get("/monitoring/history/?status=online")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Edge-Router")

        response = self.client.get("/monitoring/history/?status=offline")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "18.5 ms")


class AlertViewsAndSettingsTest(TestCase):
    """Test Alert list, acknowledgement, and threshold settings."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(
            username="alert_op", password="UserPass99!", email="op@alert.local"
        )
        self.client.login(username="alert_op", password="UserPass99!")

        self.dev = Device.objects.create(name="DB-Server-1", ip_address="10.20.1.5")
        self.alert = Alert.objects.create(
            device=self.dev,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="3 missed ICMP ping checks.",
        )

    def test_alert_list_page_renders_200(self):
        response = self.client.get("/alerts/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "alerts/alert_list.html")
        self.assertContains(response, "DB-Server-1")

    def test_alert_list_tab_filters(self):
        response = self.client.get("/alerts/?tab=active")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DB-Server-1")

        response = self.client.get("/alerts/?tab=resolved")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "DB-Server-1")

    def test_acknowledge_alert_via_post(self):
        response = self.client.post("/alerts/", {
            "alert_id": self.alert.id,
            "action": "acknowledge",
        })
        self.alert.refresh_from_db()
        self.assertTrue(self.alert.is_acknowledged)
        self.assertEqual(self.alert.acknowledged_by, self.operator)

    def test_settings_page_renders_and_updates_threshold(self):
        response = self.client.get("/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "alerts/settings.html")

        # Update threshold
        post_res = self.client.post("/settings/", {
            "high_latency_warning_ms": 120.0,
            "high_latency_critical_ms": 350.0,
            "packet_loss_warning_pct": 8.0,
            "packet_loss_critical_pct": 30.0,
            "consecutive_failures_for_offline": 4,
        })
        self.assertRedirects(post_res, "/settings/", fetch_redirect_response=False)
        t = AlertThreshold.objects.get(name="Default Global Thresholds")
        self.assertEqual(t.high_latency_warning_ms, 120.0)
        self.assertEqual(t.consecutive_failures_for_offline, 4)


class TopologyViewTest(TestCase):
    """Test Network Topology visualizer view."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="top_user", password="UserPass99!")
        self.client.login(username="top_user", password="UserPass99!")

        self.r1 = Device.objects.create(name="WAN-Router", ip_address="10.0.0.1", device_type="router")
        self.s1 = Device.objects.create(name="Core-Switch", ip_address="10.0.0.2", device_type="switch")
        self.conn = NetworkConnection.objects.create(
            source_device=self.r1,
            destination_device=self.s1,
            connection_type=NetworkConnection.ConnectionType.FIBER,
            link_speed="10 Gbps",
            is_discovered=False,
        )

    def test_topology_view_renders_200(self):
        response = self.client.get("/topology/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "topology/topology_view.html")
        ctx = response.context
        self.assertEqual(ctx["total_nodes"], 2)
        self.assertEqual(ctx["total_edges"], 1)
        self.assertEqual(ctx["manual_links"], 1)
        self.assertEqual(ctx["discovered_links"], 0)
        self.assertIn("topology_data_json", ctx)


class SidebarNavigationIntegrityTest(TestCase):
    """Test that all 10 sidebar links resolve to valid, active endpoints without ReverseNotFound."""

    def test_all_sidebar_urls_resolve(self):
        urls = [
            reverse("dashboard:overview"),
            reverse("devices:device-list"),
            reverse("topology:topology-view"),
            reverse("analytics:traffic-analytics"),
            reverse("monitoring:performance"),
            reverse("alerts:alert-list"),
            reverse("monitoring:history"),
            reverse("alerts:settings"),
            reverse("accounts:profile"),
            reverse("accounts:logout"),
        ]
        self.assertEqual(len(urls), 10)
        for u in urls:
            self.assertTrue(u.startswith("/"))
