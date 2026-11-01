"""
Test suite for Phase 9: Traffic Analytics, Chart.js Metrics & Historical Performance.

Tests:
1. bandwidth_chart_data API: time-range filtering (1h/6h/24h/7d), per-device & per-interface
   filtering, peak and average Mbps calculation
2. latency_chart_data API: RTT latency, RFC 3550 jitter, packet loss trends, summary KPIs,
   and time-range filtering
3. top_talkers_data API: top interfaces and top devices ranked by throughput, link utilization %
4. sla_summary_data API: historical DeviceDailySummary rollups, SLA target compliance (99.9%)
5. export_analytics_csv API: downloadable CSV reports for traffic, latency, and SLA
6. TrafficAnalyticsView & PerformanceMonitoringView UI enhancements
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from analytics.models import DeviceDailySummary, NetworkTrafficSnapshot
from devices.models import Device
from monitoring.models import DeviceMetric, InterfaceMetric, NetworkInterface


class BandwidthChartAnalyticsTest(TestCase):
    """Tests bandwidth_chart_data API time-range and entity filtering."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="bw_analyst", password="Password123!")
        self.client.force_login(self.user)

        now = timezone.now()
        self.dev1 = Device.objects.create(name="Core-Rtr-1", ip_address="10.90.1.1")
        self.dev2 = Device.objects.create(name="Edge-Sw-1", ip_address="10.90.1.2")

        self.iface1 = NetworkInterface.objects.create(
            device=self.dev1,
            interface_name="Gi0/0",
            interface_index=1,
            speed_bps=1_000_000_000,
            operational_status="up",
        )
        self.iface2 = NetworkInterface.objects.create(
            device=self.dev2,
            interface_name="Gi0/1",
            interface_index=2,
            speed_bps=100_000_000,
            operational_status="up",
        )

        # Snapshot 3 hours ago (outside 1h range, inside 6h range)
        NetworkTrafficSnapshot.objects.create(
            recorded_at=now - timedelta(hours=3),
            total_devices=2,
            online_devices=2,
            total_incoming_bps=10_000_000.0,
            total_outgoing_bps=5_000_000.0,
        )
        # Snapshot 15 minutes ago (inside 1h range)
        NetworkTrafficSnapshot.objects.create(
            recorded_at=now - timedelta(minutes=15),
            total_devices=2,
            online_devices=2,
            total_incoming_bps=40_000_000.0,
            total_outgoing_bps=20_000_000.0,
        )

        # Interface metrics
        InterfaceMetric.objects.create(
            interface=self.iface1,
            incoming_bytes=500000,
            outgoing_bytes=250000,
            incoming_bps=50_000_000.0,
            outgoing_bps=25_000_000.0,
            recorded_at=now - timedelta(minutes=10),
        )
        InterfaceMetric.objects.create(
            interface=self.iface2,
            incoming_bytes=100000,
            outgoing_bytes=100000,
            incoming_bps=12_000_000.0,
            outgoing_bps=8_000_000.0,
            recorded_at=now - timedelta(minutes=10),
        )

    def test_bandwidth_chart_returns_peak_and_average_metrics(self):
        res = self.client.get(reverse("analytics:bandwidth-chart"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["labels"]), 2)
        self.assertEqual(data["current_incoming_mbps"], 40.0)
        self.assertEqual(data["current_outgoing_mbps"], 20.0)
        self.assertEqual(data["peak_incoming_mbps"], 40.0)
        self.assertEqual(data["avg_incoming_mbps"], 25.0)

    def test_bandwidth_chart_1h_range_filters_out_older_snapshots(self):
        res = self.client.get(reverse("analytics:bandwidth-chart") + "?range=1h")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["labels"]), 1)
        self.assertEqual(data["incoming_mbps"], [40.0])

    def test_bandwidth_chart_per_interface_and_per_device_filtering(self):
        res_iface = self.client.get(
            f"{reverse('analytics:bandwidth-chart')}?interface_id={self.iface1.id}"
        )
        self.assertEqual(res_iface.status_code, 200)
        d_if = res_iface.json()
        self.assertEqual(d_if["current_incoming_mbps"], 50.0)
        self.assertEqual(d_if["current_outgoing_mbps"], 25.0)

        res_dev = self.client.get(
            f"{reverse('analytics:bandwidth-chart')}?device_id={self.dev2.id}"
        )
        self.assertEqual(res_dev.status_code, 200)
        d_dev = res_dev.json()
        self.assertEqual(d_dev["current_incoming_mbps"], 12.0)
        self.assertEqual(d_dev["current_outgoing_mbps"], 8.0)


class LatencyJitterAnalyticsTest(TestCase):
    """Tests latency_chart_data API including jitter and summary KPIs."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="lat_analyst", password="Password123!")
        self.client.force_login(self.user)

        now = timezone.now()
        self.device = Device.objects.create(name="WAN-Gateway", ip_address="10.91.1.1")
        DeviceMetric.objects.create(
            device=self.device,
            status="online",
            latency=10.0,
            jitter=1.0,
            packet_loss=0.0,
            recorded_at=now - timedelta(hours=4),
        )
        DeviceMetric.objects.create(
            device=self.device,
            status="online",
            latency=20.0,
            jitter=2.5,
            packet_loss=2.0,
            recorded_at=now - timedelta(minutes=20),
        )
        DeviceMetric.objects.create(
            device=self.device,
            status="online",
            latency=30.0,
            jitter=3.5,
            packet_loss=4.0,
            recorded_at=now - timedelta(minutes=5),
        )

    def test_latency_chart_includes_jitter_and_summary_stats(self):
        res = self.client.get(
            f"{reverse('analytics:latency-chart')}?device_id={self.device.id}"
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("jitter_ms", data)
        self.assertEqual(data["latency_ms"], [10.0, 20.0, 30.0])
        self.assertEqual(data["jitter_ms"], [1.0, 2.5, 3.5])
        summary = data["summary"]
        self.assertEqual(summary["min_latency_ms"], 10.0)
        self.assertEqual(summary["avg_latency_ms"], 20.0)
        self.assertEqual(summary["max_latency_ms"], 30.0)
        self.assertEqual(summary["avg_jitter_ms"], 2.33)
        self.assertEqual(summary["samples_count"], 3)

    def test_latency_chart_respects_1h_time_range(self):
        res = self.client.get(
            f"{reverse('analytics:latency-chart')}?device_id={self.device.id}&range=1h"
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["labels"]), 2)
        self.assertEqual(data["latency_ms"], [20.0, 30.0])


class TopTalkersAndSLASummaryTest(TestCase):
    """Tests top_talkers_data and sla_summary_data APIs."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="sla_analyst", password="Password123!")
        self.client.force_login(self.user)

        self.dev_high = Device.objects.create(name="High-BW-Router", ip_address="10.92.1.1")
        self.dev_low = Device.objects.create(name="Low-BW-Switch", ip_address="10.92.1.2")

        self.if_high = NetworkInterface.objects.create(
            device=self.dev_high,
            interface_name="TenGig0/0",
            interface_index=1,
            speed_bps=100_000_000,  # 100 Mbps link
            operational_status="up",
        )
        self.if_low = NetworkInterface.objects.create(
            device=self.dev_low,
            interface_name="Fa0/1",
            interface_index=1,
            speed_bps=100_000_000,
            operational_status="up",
        )

        # 80 Mbps in + 20 Mbps out on 100 Mbps link => 80% utilization
        InterfaceMetric.objects.create(
            interface=self.if_high,
            incoming_bps=80_000_000.0,
            outgoing_bps=20_000_000.0,
        )
        InterfaceMetric.objects.create(
            interface=self.if_low,
            incoming_bps=5_000_000.0,
            outgoing_bps=2_000_000.0,
        )

        today = timezone.now().date()
        DeviceDailySummary.objects.create(
            device=self.dev_high,
            date=today - timedelta(days=1),
            uptime_percentage=99.95,
            avg_latency=12.0,
            max_latency=25.0,
            total_alerts_count=0,
        )
        DeviceDailySummary.objects.create(
            device=self.dev_high,
            date=today,
            uptime_percentage=100.00,
            avg_latency=11.0,
            max_latency=20.0,
            total_alerts_count=0,
        )

    def test_top_talkers_ranks_interfaces_and_computes_utilization(self):
        res = self.client.get(reverse("analytics:top-talkers"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["top_interfaces"]), 2)
        first = data["top_interfaces"][0]
        self.assertEqual(first["interface_name"], "TenGig0/0")
        self.assertEqual(first["total_mbps"], 100.0)
        self.assertEqual(first["utilization_pct"], 80.0)

        self.assertEqual(data["top_devices"][0]["device_name"], "High-BW-Router")
        self.assertEqual(data["top_devices"][0]["total_mbps"], 100.0)

    def test_sla_summary_api_returns_daily_rollups_and_compliance(self):
        res = self.client.get(
            f"{reverse('analytics:sla-summary')}?device_id={self.dev_high.id}&days=7"
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["labels"]), 2)
        self.assertEqual(data["uptime_pct"], [99.95, 100.0])
        self.assertGreaterEqual(data["overall_sla_pct"], 99.9)
        self.assertTrue(data["sla_compliant"])


class CSVReportExportTest(TestCase):
    """Tests export_analytics_csv endpoint for traffic, latency, and SLA reports."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="csv_user", password="Password123!")
        self.client.force_login(self.user)

        self.device = Device.objects.create(name="CSV-Device", ip_address="10.93.1.1")
        NetworkTrafficSnapshot.objects.create(
            total_devices=1,
            online_devices=1,
            total_incoming_bps=15_000_000.0,
            total_outgoing_bps=5_000_000.0,
        )
        DeviceMetric.objects.create(
            device=self.device,
            status="online",
            latency=14.2,
            jitter=1.1,
            packet_loss=0.0,
        )
        DeviceDailySummary.objects.create(
            device=self.device,
            date=timezone.now().date(),
            uptime_percentage=99.98,
            avg_latency=14.2,
        )

    def test_export_traffic_csv(self):
        res = self.client.get(reverse("analytics:export-csv") + "?type=traffic&range=24h")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res["Content-Type"], "text/csv")
        content = res.content.decode("utf-8")
        self.assertIn("Total Bandwidth (Mbps)", content)
        self.assertIn("20.0", content)

    def test_export_latency_csv(self):
        res = self.client.get(
            f"{reverse('analytics:export-csv')}?type=latency&device_id={self.device.id}"
        )
        self.assertEqual(res.status_code, 200)
        content = res.content.decode("utf-8")
        self.assertIn("Latency (ms)", content)
        self.assertIn("CSV-Device", content)
        self.assertIn("14.2", content)

    def test_export_sla_csv(self):
        res = self.client.get(
            f"{reverse('analytics:export-csv')}?type=sla&device_id={self.device.id}"
        )
        self.assertEqual(res.status_code, 200)
        content = res.content.decode("utf-8")
        self.assertIn("Uptime (%)", content)
        self.assertIn("99.98", content)


class Phase9ViewsTemplateIntegrationTest(TestCase):
    """Tests that Traffic Analytics and Performance views render Phase 9 charts & controls."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="p9_ui_user", password="Password123!")
        self.client.force_login(self.user)
        self.device = Device.objects.create(name="P9-Router", ip_address="10.94.1.1")
        self.iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="Gi0/0/1",
            interface_index=1,
            speed_bps=1_000_000_000,
            operational_status="up",
        )
        InterfaceMetric.objects.create(
            interface=self.iface,
            incoming_bps=250_000_000.0,
            outgoing_bps=100_000_000.0,
        )

    def test_traffic_analytics_page_includes_top_talkers_and_utilization(self):
        res = self.client.get(reverse("analytics:traffic-analytics"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn('id="topTalkersChart"', html)
        self.assertIn('id="btn-export-traffic-csv"', html)
        self.assertIn("25.0%", html)  # 250 Mbps on 1 Gbps link = 25.0% utilization

    def test_performance_monitoring_page_includes_jitter_and_sla_chart(self):
        res = self.client.get(reverse("monitoring:performance"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn('id="slaHistoryChart"', html)
        self.assertIn('id="perf-avg-jitter"', html)
        self.assertIn('id="btn-export-perf-csv"', html)
