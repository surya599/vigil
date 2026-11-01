"""
Test suite for Phase 7: NetPulse Celery Background Monitoring & Celery Beat.

Tests:
1. task_icmp_check_device (execution, lock deduplication, disabled device handling)
2. task_icmp_sweep (batch polling, sweep locking)
3. task_snmp_poll_device (execution, lock deduplication, disabled SNMP handling)
4. task_snmp_sweep (batch polling, sweep locking)
5. task_aggregate_traffic_snapshots (network-wide rollup, NetworkTrafficSnapshot creation)
6. task_generate_daily_summaries (device uptime %, SLA calculation, DeviceDailySummary creation)
7. task_cleanup_historical_metrics (pruning metrics older than retention period)
8. Celery Beat periodic schedule configuration integrity
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch
from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from alerts.models import Alert
from analytics.models import DeviceDailySummary, NetworkTrafficSnapshot
from config.celery import app as celery_app
from devices.models import Device
from monitoring.icmp import ICMPResult
from monitoring.models import DeviceMetric, InterfaceMetric, NetworkInterface
from monitoring.snmp import SNMPInterfaceData, SNMPSystemData
from monitoring.tasks import (
    task_aggregate_traffic_snapshots,
    task_cleanup_historical_metrics,
    task_generate_daily_summaries,
    task_icmp_check_device,
    task_icmp_sweep,
    task_snmp_poll_device,
    task_snmp_sweep,
)


class CeleryBeatConfigurationTest(TestCase):
    """Verifies that Celery Beat periodic schedules are correctly configured and registered."""

    def test_all_beat_tasks_are_registered_in_celery(self):
        beat_schedule = getattr(settings, "CELERY_BEAT_SCHEDULE", {})
        self.assertGreaterEqual(len(beat_schedule), 5)

        for name, entry in beat_schedule.items():
            task_name = entry["task"]
            self.assertIn(
                task_name,
                celery_app.tasks,
                f"Celery Beat task '{task_name}' in schedule '{name}' is not registered with Celery.",
            )
            self.assertIn("schedule", entry)
            self.assertGreater(entry["schedule"], 0)


class ICMPCeleryTasksTest(TestCase):
    """Tests single and batch ICMP Celery tasks."""

    def setUp(self):
        cache.clear()
        self.device = Device.objects.create(
            name="Celery-Router",
            ip_address="10.210.1.1",
            device_type=Device.DeviceType.ROUTER,
            monitoring_enabled=True,
        )

    def tearDown(self):
        cache.clear()

    def test_task_icmp_check_device_success(self):
        mock_metric = DeviceMetric(
            device=self.device,
            status=Device.Status.ONLINE,
            latency=12.5,
            packet_loss=0.0,
            jitter=1.2,
        )
        with patch("monitoring.icmp.ICMPMonitoringEngine.check_device", return_value=mock_metric):
            res = task_icmp_check_device.apply(args=[self.device.id]).get()

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["device_status"], "online")
        self.assertEqual(res["latency"], 12.5)
        self.assertEqual(res["packet_loss"], 0.0)

    def test_task_icmp_check_device_skips_when_locked(self):
        # Manually lock device
        lock_key = f"netpulse:lock:icmp:{self.device.id}"
        cache.set(lock_key, "locked", timeout=60)

        res = task_icmp_check_device.apply(args=[self.device.id]).get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "device_locked")

    def test_task_icmp_check_device_skips_disabled_device(self):
        self.device.monitoring_enabled = False
        self.device.save()

        res = task_icmp_check_device.apply(args=[self.device.id]).get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "monitoring_disabled")

    def test_task_icmp_check_device_not_found(self):
        res = task_icmp_check_device.apply(args=[999999]).get()
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["reason"], "device_not_found")

    def test_task_icmp_sweep_executes_and_returns_summary(self):
        mock_summary = {
            "total": 3,
            "online": 2,
            "warning": 1,
            "offline": 0,
            "elapsed_seconds": 1.25,
        }
        with patch("monitoring.icmp.ICMPMonitoringEngine.check_all_devices", return_value=mock_summary):
            res = task_icmp_sweep.apply().get()

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total"], 3)
        self.assertEqual(res["online"], 2)

    def test_task_icmp_sweep_skips_when_sweep_locked(self):
        cache.set("netpulse:lock:icmp:sweep", "locked", timeout=60)
        res = task_icmp_sweep.apply().get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "sweep_already_running")


class SNMPCeleryTasksTest(TestCase):
    """Tests single and batch SNMP Celery tasks."""

    def setUp(self):
        cache.clear()
        self.device = Device.objects.create(
            name="Celery-SNMP-Switch",
            ip_address="10.220.1.1",
            device_type=Device.DeviceType.SWITCH,
            snmp_enabled=True,
            monitoring_enabled=True,
        )

    def tearDown(self):
        cache.clear()

    def test_task_snmp_poll_device_success(self):
        mock_data = SNMPSystemData(
            sys_description="Managed Switch OS",
            sys_uptime="10d 04h",
            interfaces=[SNMPInterfaceData(index=1, name="eth0", oper_status="up")],
            is_successful=True,
        )
        with patch("monitoring.snmp.SNMPMonitoringEngine.poll_device", return_value=mock_data):
            res = task_snmp_poll_device.apply(args=[self.device.id]).get()

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_successful"])
        self.assertEqual(res["interfaces_count"], 1)

    def test_task_snmp_poll_device_skips_when_locked(self):
        lock_key = f"netpulse:lock:snmp:{self.device.id}"
        cache.set(lock_key, "locked", timeout=120)

        res = task_snmp_poll_device.apply(args=[self.device.id]).get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "device_locked")

    def test_task_snmp_poll_device_skips_when_snmp_disabled(self):
        self.device.snmp_enabled = False
        self.device.save()

        res = task_snmp_poll_device.apply(args=[self.device.id]).get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "snmp_disabled")

    def test_task_snmp_sweep_executes_and_returns_summary(self):
        mock_summary = {
            "total": 4,
            "successful": 4,
            "failed": 0,
            "elapsed_seconds": 2.1,
        }
        with patch("monitoring.snmp.SNMPMonitoringEngine.poll_all_snmp_devices", return_value=mock_summary):
            res = task_snmp_sweep.apply().get()

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total"], 4)
        self.assertEqual(res["successful"], 4)

    def test_task_snmp_sweep_skips_when_sweep_locked(self):
        cache.set("netpulse:lock:snmp:sweep", "locked", timeout=120)
        res = task_snmp_sweep.apply().get()
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "sweep_already_running")


class HistoricalAnalyticsTasksTest(TestCase):
    """Tests network traffic snapshots, daily summaries, and metric pruning."""

    def setUp(self):
        self.device1 = Device.objects.create(
            name="Analytics-Dev-1",
            ip_address="10.230.1.1",
            status=Device.Status.ONLINE,
            monitoring_enabled=True,
        )
        self.device2 = Device.objects.create(
            name="Analytics-Dev-2",
            ip_address="10.230.1.2",
            status=Device.Status.OFFLINE,
            monitoring_enabled=True,
        )
        self.iface1 = NetworkInterface.objects.create(
            device=self.device1,
            interface_name="eth0",
            interface_index=1,
            operational_status="up",
        )
        now = timezone.now()
        # Create metrics within past 2 minutes
        DeviceMetric.objects.create(
            device=self.device1,
            status=Device.Status.ONLINE,
            latency=15.0,
            packet_loss=0.0,
            recorded_at=now - timedelta(minutes=1),
        )
        DeviceMetric.objects.create(
            device=self.device2,
            status=Device.Status.OFFLINE,
            latency=None,
            packet_loss=100.0,
            recorded_at=now - timedelta(minutes=1),
        )
        InterfaceMetric.objects.create(
            interface=self.iface1,
            incoming_bytes=1000000,
            outgoing_bytes=500000,
            incoming_bps=10_000_000.0,  # 10 Mbps
            outgoing_bps=5_000_000.0,   # 5 Mbps
            recorded_at=now - timedelta(minutes=1),
        )

    def test_task_aggregate_traffic_snapshots_creates_snapshot(self):
        res = task_aggregate_traffic_snapshots.apply().get()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_devices"], 2)
        self.assertEqual(res["online_devices"], 1)
        self.assertEqual(res["offline_devices"], 1)

        # Verify record in database
        snapshot = NetworkTrafficSnapshot.objects.get(id=res["snapshot_id"])
        self.assertEqual(snapshot.total_devices, 2)
        self.assertEqual(snapshot.online_devices, 1)
        self.assertEqual(snapshot.total_incoming_bps, 10_000_000.0)
        self.assertEqual(snapshot.total_outgoing_bps, 5_000_000.0)
        self.assertEqual(snapshot.average_latency, 15.0)

    def test_task_generate_daily_summaries(self):
        # Create an alert for device 2
        Alert.objects.create(
            device=self.device2,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            severity=Alert.Severity.CRITICAL,
            description="Outage",
            created_at=timezone.now(),
        )

        res = task_generate_daily_summaries.apply().get()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["devices_processed"], 2)

        today = timezone.now().date()
        summary1 = DeviceDailySummary.objects.get(device=self.device1, date=today)
        self.assertEqual(float(summary1.uptime_percentage), 100.0)
        self.assertEqual(summary1.avg_latency, 15.0)

        summary2 = DeviceDailySummary.objects.get(device=self.device2, date=today)
        self.assertEqual(float(summary2.uptime_percentage), 0.0)
        self.assertEqual(summary2.total_alerts_count, 1)

    def test_task_cleanup_historical_metrics_prunes_old_records(self):
        now = timezone.now()
        # Metric 40 days old (should be pruned)
        old_dev_metric = DeviceMetric.objects.create(
            device=self.device1,
            status=Device.Status.ONLINE,
            latency=10.0,
            recorded_at=now - timedelta(days=40),
        )
        old_if_metric = InterfaceMetric.objects.create(
            interface=self.iface1,
            incoming_bytes=100,
            outgoing_bytes=100,
            recorded_at=now - timedelta(days=40),
        )
        # Metric 5 days old (should be kept)
        recent_dev_metric = DeviceMetric.objects.create(
            device=self.device1,
            status=Device.Status.ONLINE,
            latency=10.0,
            recorded_at=now - timedelta(days=5),
        )

        res = task_cleanup_historical_metrics.apply(kwargs={"retention_days": 30}).get()
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["device_metrics_deleted"], 1)
        self.assertGreaterEqual(res["interface_metrics_deleted"], 1)

        # Verify old metrics deleted and recent kept
        self.assertFalse(DeviceMetric.objects.filter(id=old_dev_metric.id).exists())
        self.assertFalse(InterfaceMetric.objects.filter(id=old_if_metric.id).exists())
        self.assertTrue(DeviceMetric.objects.filter(id=recent_dev_metric.id).exists())
