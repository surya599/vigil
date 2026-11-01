"""
NetPulse Celery Background Monitoring Tasks.

Provides asynchronous and periodic worker tasks for:
1. Device ICMP health checks (single device and batch sweeps)
2. SNMP metadata and interface telemetry polling
3. Concurrency locking using cache to prevent overlapping duplicate runs for the same device
4. Network traffic snapshot aggregation for high-performance NOC charts
5. Daily SLA and availability summary generation
6. Automatic retention cleanup for historical metrics
"""

import logging
import time
from datetime import timedelta
from typing import Optional

from celery import shared_task
from django.core.cache import cache
from django.db.models import Avg, Sum
from django.utils import timezone

from alerts.models import Alert
from analytics.models import DeviceDailySummary, NetworkTrafficSnapshot
from devices.models import Device
from monitoring.icmp import ICMPMonitoringEngine
from monitoring.models import DeviceMetric, InterfaceMetric, NetworkInterface
from monitoring.snmp import SNMPMonitoringEngine

logger = logging.getLogger("netpulse.monitoring.tasks")


# ─── 1. ICMP Polling Tasks ───────────────────────────────────────────────────

@shared_task(
    name="monitoring.tasks.task_icmp_check_device",
    bind=True,
    max_retries=2,
    default_retry_delay=5,
)
def task_icmp_check_device(self, device_id: int, count: int = 4, timeout: float = 1.0):
    """
    Asynchronously conducts an ICMP availability check on a single device.
    Uses a cache lock to guarantee that duplicate checks for the same device
    do not run concurrently.
    """
    lock_key = f"netpulse:lock:icmp:{device_id}"
    # Acquire lock with 60s timeout
    acquired = cache.add(lock_key, "locked", timeout=60)
    if not acquired:
        logger.info("ICMP check for device ID %d is already in progress, skipping duplicate.", device_id)
        return {"status": "skipped", "reason": "device_locked", "device_id": device_id}

    try:
        device = Device.objects.get(id=device_id)
        if not device.monitoring_enabled:
            return {"status": "skipped", "reason": "monitoring_disabled", "device_id": device_id}

        engine = ICMPMonitoringEngine()
        metric = engine.check_device(device, packet_count=count, timeout=timeout)

        logger.info(
            "ICMP task completed for '%s' (%s): status=%s, rtt=%.1fms, loss=%.1f%%",
            device.name,
            device.ip_address,
            metric.status,
            metric.latency or 0.0,
            metric.packet_loss,
        )
        return {
            "status": "success",
            "device_id": device.id,
            "device_name": device.name,
            "device_status": metric.status,
            "latency": metric.latency,
            "packet_loss": metric.packet_loss,
            "jitter": metric.jitter,
            "consecutive_failures": device.consecutive_failures,
        }
    except Device.DoesNotExist:
        logger.error("Device ID %d not found for ICMP check.", device_id)
        return {"status": "error", "reason": "device_not_found", "device_id": device_id}
    except Exception as exc:
        logger.error("Error in task_icmp_check_device for ID %d: %s", device_id, exc, exc_info=True)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.critical("Max retries exceeded for ICMP task on device ID %d", device_id)
            return {"status": "error", "reason": str(exc), "device_id": device_id}
    finally:
        cache.delete(lock_key)


@shared_task(name="monitoring.tasks.task_icmp_sweep")
def task_icmp_sweep(workers: int = 10, count: int = 4, timeout: float = 1.0):
    """
    Periodic task: Sweeps all monitored devices across the network in parallel.
    Uses a sweep lock to avoid overlapping sweeps if a cycle runs long.
    """
    lock_key = "netpulse:lock:icmp:sweep"
    acquired = cache.add(lock_key, "locked", timeout=55)
    if not acquired:
        logger.warning("ICMP sweep is already running. Skipping this periodic cycle.")
        return {"status": "skipped", "reason": "sweep_already_running"}

    try:
        engine = ICMPMonitoringEngine()
        summary = engine.check_all_devices(
            max_workers=workers,
            packet_count=count,
            timeout=timeout,
        )
        logger.info(
            "ICMP sweep completed: %d devices checked in %.2fs (%d online, %d warning, %d offline)",
            summary["total"],
            summary["elapsed_seconds"],
            summary["online"],
            summary["warning"],
            summary["offline"],
        )
        return {
            "status": "success",
            "total": summary["total"],
            "online": summary["online"],
            "warning": summary["warning"],
            "offline": summary["offline"],
            "elapsed_seconds": summary["elapsed_seconds"],
        }
    finally:
        cache.delete(lock_key)


# ─── 2. SNMP Polling Tasks ───────────────────────────────────────────────────

@shared_task(
    name="monitoring.tasks.task_snmp_poll_device",
    bind=True,
    max_retries=2,
    default_retry_delay=10,
)
def task_snmp_poll_device(self, device_id: int, timeout: float = 2.0):
    """
    Asynchronously interrogates an SNMP-enabled device for system description,
    uptime, interface inventory, and traffic octet counters.
    Guaranteed no duplicate executions using per-device cache lock.
    """
    lock_key = f"netpulse:lock:snmp:{device_id}"
    acquired = cache.add(lock_key, "locked", timeout=120)
    if not acquired:
        logger.info("SNMP poll for device ID %d is already running, skipping duplicate.", device_id)
        return {"status": "skipped", "reason": "device_locked", "device_id": device_id}

    try:
        device = Device.objects.get(id=device_id)
        if not device.snmp_enabled or not device.monitoring_enabled:
            return {"status": "skipped", "reason": "snmp_disabled", "device_id": device_id}

        engine = SNMPMonitoringEngine()
        data = engine.poll_device(device, timeout=timeout)

        logger.info(
            "SNMP task completed for '%s' (%s): success=%s, interfaces=%d",
            device.name,
            device.ip_address,
            data.is_successful,
            len(data.interfaces),
        )
        return {
            "status": "success" if data.is_successful else "failed",
            "device_id": device.id,
            "device_name": device.name,
            "is_successful": data.is_successful,
            "sys_description": data.sys_description[:80] if data.sys_description else "",
            "sys_uptime": data.sys_uptime,
            "interfaces_count": len(data.interfaces),
            "error_message": data.error_message,
        }
    except Device.DoesNotExist:
        logger.error("Device ID %d not found for SNMP poll.", device_id)
        return {"status": "error", "reason": "device_not_found", "device_id": device_id}
    except Exception as exc:
        logger.error("Error in task_snmp_poll_device for ID %d: %s", device_id, exc, exc_info=True)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {"status": "error", "reason": str(exc), "device_id": device_id}
    finally:
        cache.delete(lock_key)


@shared_task(name="monitoring.tasks.task_snmp_sweep")
def task_snmp_sweep(workers: int = 5, timeout: float = 2.0):
    """
    Periodic task: Sweeps all SNMP-enabled devices across the network in parallel.
    Uses a sweep lock to avoid overlapping runs.
    """
    lock_key = "netpulse:lock:snmp:sweep"
    acquired = cache.add(lock_key, "locked", timeout=110)
    if not acquired:
        logger.warning("SNMP sweep is already running. Skipping this periodic cycle.")
        return {"status": "skipped", "reason": "sweep_already_running"}

    try:
        engine = SNMPMonitoringEngine()
        summary = engine.poll_all_snmp_devices(max_workers=workers, timeout=timeout)
        logger.info(
            "SNMP sweep completed: %d devices in %.2fs (%d successful, %d failed)",
            summary["total"],
            summary["elapsed_seconds"],
            summary["successful"],
            summary["failed"],
        )
        return {
            "status": "success",
            "total": summary["total"],
            "successful": summary["successful"],
            "failed": summary["failed"],
            "elapsed_seconds": summary["elapsed_seconds"],
        }
    finally:
        cache.delete(lock_key)


# ─── 3. Historical Data & Analytics Processing Tasks ──────────────────────────

@shared_task(name="monitoring.tasks.task_aggregate_traffic_snapshots")
def task_aggregate_traffic_snapshots():
    """
    Periodic task: Computes and records a NetworkTrafficSnapshot capturing
    network-wide aggregate traffic rates (bps), device availability distribution,
    and average latency/packet loss across the entire NOC.
    """
    now = timezone.now()
    window_start = now - timedelta(minutes=5)

    total_devices = Device.objects.count()
    online_devices = Device.objects.filter(status=Device.Status.ONLINE).count()
    offline_devices = Device.objects.filter(status=Device.Status.OFFLINE).count()
    warning_devices = Device.objects.filter(status=Device.Status.WARNING).count()

    # Average latency and packet loss from recent metrics
    recent_metrics = DeviceMetric.objects.filter(recorded_at__gte=window_start)
    avg_stats = recent_metrics.aggregate(
        avg_lat=Avg("latency"),
        avg_loss=Avg("packet_loss"),
    )
    avg_latency = round(avg_stats["avg_lat"] or 0.0, 2)
    avg_loss = round(avg_stats["avg_loss"] or 0.0, 2)

    # Sum traffic bps across all interface metrics recorded in the past 5-minute window.
    # Summing directly is correct for snapshot aggregation (we want total network throughput,
    # not per-interface deduplication), and avoids PostgreSQL DISTINCT ON ordering constraints.
    traffic_sums = InterfaceMetric.objects.filter(
        recorded_at__gte=window_start
    ).aggregate(
        total_in=Sum("incoming_bps"),
        total_out=Sum("outgoing_bps"),
    )
    total_in_bps = round(traffic_sums["total_in"] or 0.0, 2)
    total_out_bps = round(traffic_sums["total_out"] or 0.0, 2)

    snapshot = NetworkTrafficSnapshot.objects.create(
        recorded_at=now,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        warning_devices=warning_devices,
        average_latency=avg_latency,
        average_packet_loss=avg_loss,
        total_incoming_bps=total_in_bps,
        total_outgoing_bps=total_out_bps,
    )

    logger.info(
        "Recorded NetworkTrafficSnapshot #%d at %s: in=%.2f Mbps, out=%.2f Mbps, online=%d/%d",
        snapshot.id,
        now.strftime("%H:%M:%S"),
        total_in_bps / 1_000_000.0,
        total_out_bps / 1_000_000.0,
        online_devices,
        total_devices,
    )
    return {
        "status": "success",
        "snapshot_id": snapshot.id,
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": offline_devices,
        "total_incoming_bps": total_in_bps,
        "total_outgoing_bps": total_out_bps,
    }


@shared_task(name="monitoring.tasks.task_generate_daily_summaries")
def task_generate_daily_summaries(target_date_str: Optional[str] = None):
    """
    Rolls up daily SLA and performance metrics into DeviceDailySummary records.
    Computes uptime percentage, min/avg/max latency, and incident counts per device.
    """
    now = timezone.now()
    if target_date_str:
        from datetime import datetime
        target_date = datetime.strptime(target_date_str, "%Y-%m-%d").date()
    else:
        target_date = now.date()

    day_start = timezone.make_aware(
        timezone.datetime.combine(target_date, timezone.datetime.min.time())
    )
    day_end = timezone.make_aware(
        timezone.datetime.combine(target_date, timezone.datetime.max.time())
    )

    devices = Device.objects.filter(monitoring_enabled=True)
    created_or_updated = 0

    for dev in devices:
        metrics_qs = dev.metrics.filter(recorded_at__range=(day_start, day_end))
        total_polls = metrics_qs.count()

        if total_polls > 0:
            online_polls = metrics_qs.exclude(status=Device.Status.OFFLINE).count()
            uptime_pct = round((online_polls / total_polls) * 100.0, 2)
            downtime_sec = int((86400 * (100.0 - float(uptime_pct))) / 100.0)
            uptime_sec = 86400 - downtime_sec

            stats = metrics_qs.aggregate(
                avg_lat=Avg("latency"),
                avg_loss=Avg("packet_loss"),
            )
            # Find max latency
            max_metric = metrics_qs.exclude(latency__isnull=True).order_by("-latency").first()
            max_lat = max_metric.latency if max_metric and max_metric.latency else 0.0

            avg_lat = round(stats["avg_lat"] or 0.0, 2)
            avg_loss = round(stats["avg_loss"] or 0.0, 2)
        else:
            uptime_pct = 100.0 if dev.status != Device.Status.OFFLINE else 0.0
            uptime_sec = 86400 if uptime_pct == 100.0 else 0
            downtime_sec = 86400 - uptime_sec
            avg_lat = 0.0
            max_lat = 0.0
            avg_loss = 0.0

        alerts_count = dev.alerts.filter(created_at__range=(day_start, day_end)).count()

        DeviceDailySummary.objects.update_or_create(
            device=dev,
            date=target_date,
            defaults={
                "uptime_seconds": uptime_sec,
                "downtime_seconds": downtime_sec,
                "uptime_percentage": uptime_pct,
                "avg_latency": avg_lat,
                "max_latency": max_lat,
                "avg_packet_loss": avg_loss,
                "total_alerts_count": alerts_count,
            },
        )
        created_or_updated += 1

    logger.info("Generated DeviceDailySummary for %d devices on %s", created_or_updated, target_date)
    return {
        "status": "success",
        "date": str(target_date),
        "devices_processed": created_or_updated,
    }


@shared_task(name="monitoring.tasks.task_cleanup_historical_metrics")
def task_cleanup_historical_metrics(retention_days: int = 30):
    """
    Prunes high-frequency DeviceMetric and InterfaceMetric entries older than
    retention_days to preserve database performance.
    """
    cutoff = timezone.now() - timedelta(days=retention_days)
    dev_deleted, _ = DeviceMetric.objects.filter(recorded_at__lt=cutoff).delete()
    if_deleted, _ = InterfaceMetric.objects.filter(recorded_at__lt=cutoff).delete()

    logger.info(
        "Historical cleanup: pruned %d device metrics and %d interface metrics older than %s",
        dev_deleted,
        if_deleted,
        cutoff.strftime("%Y-%m-%d"),
    )
    return {
        "status": "success",
        "retention_days": retention_days,
        "device_metrics_deleted": dev_deleted,
        "interface_metrics_deleted": if_deleted,
    }
