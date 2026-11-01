"""
NetPulse ICMP Monitoring Engine.

Provides independent, high-precision ICMP polling, packet loss calculation,
response time and jitter measurement, consecutive failure tracking, and
device availability transitions.

Supports:
1. ping3 raw socket ping (primary)
2. Subprocess cross-platform system ping fallback (Windows 'ping -n', Linux/macOS 'ping -c')
3. Thread-safe concurrent multi-device polling without blocking web requests
4. Automatic Alert generation on failure and self-healing on recovery
"""

import logging
import platform
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List, Optional, Tuple

import ping3
from django.db import close_old_connections
from django.utils import timezone

logger = logging.getLogger("netpulse.monitoring.icmp")


@dataclass
class ICMPResult:
    """Encapsulates the outcome of an ICMP ping inspection across sample packets."""
    ip_address: str
    packets_sent: int
    packets_received: int
    packet_loss: float
    latencies: List[float] = field(default_factory=list)
    min_latency: Optional[float] = None
    avg_latency: Optional[float] = None
    max_latency: Optional[float] = None
    jitter: Optional[float] = None
    is_reachable: bool = False
    error_message: Optional[str] = None


class ICMPChecker:
    """
    Executes ICMP echo requests against a target IP address.
    Uses ping3 by default and falls back to system ping if raw sockets
    are restricted by operating system privileges.
    """

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.system = platform.system().lower()

    def ping_once_ping3(self, ip_address: str, timeout: Optional[float] = None) -> Optional[float]:
        """
        Executes a single ICMP echo request using ping3.
        Returns round-trip time in milliseconds (float) or None if timed out/unreachable.
        Raises OSError/PermissionError if raw sockets are forbidden.
        """
        to = timeout if timeout is not None else self.timeout
        # ping3 takes timeout in seconds and unit='ms'
        result = ping3.ping(ip_address, unit="ms", timeout=to)
        if result is False or result is None:
            return None
        return float(result)

    def ping_once_system(self, ip_address: str, timeout: Optional[float] = None) -> Optional[float]:
        """
        Fallback: executes an OS-native ping command and parses stdout for round-trip latency.
        Supports Windows ('ping -n 1 -w <ms>') and Linux/macOS ('ping -c 1 -W <sec>').
        """
        to = timeout if timeout is not None else self.timeout
        timeout_ms = int(to * 1000)

        if "windows" in self.system:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
        else:
            # Linux / macOS
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(to))), ip_address]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=to + 1.5,
                check=False,
            )
            stdout = proc.stdout

            # Windows pattern: "time<1ms" or "time=12ms" or "time=12.4ms"
            # Linux pattern: "time=12.3 ms"
            match = re.search(r"time[<=]([0-9.]+)\s*ms", stdout, re.IGNORECASE)
            if match:
                val = float(match.group(1))
                return max(0.1, val)

            # Check if timed out or host unreachable
            if "timed out" in stdout.lower() or "unreachable" in stdout.lower() or proc.returncode != 0:
                return None
            return None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception) as exc:
            logger.debug("System ping fallback exception for %s: %s", ip_address, exc)
            return None

    def ping_once(self, ip_address: str, timeout: Optional[float] = None) -> Optional[float]:
        """
        Sends a single ping using ping3 first, falling back to system ping on permission errors.
        """
        to = timeout if timeout is not None else self.timeout
        try:
            return self.ping_once_ping3(ip_address, timeout=to)
        except (PermissionError, OSError, Exception) as exc:
            logger.debug("ping3 raw socket unviable (%s), using system ping for %s", exc, ip_address)
            return self.ping_once_system(ip_address, timeout=to)

    def ping_host(
        self,
        ip_address: str,
        count: int = 4,
        timeout: Optional[float] = None,
        interval: float = 0.15,
    ) -> ICMPResult:
        """
        Performs multi-packet ICMP sampling to compute packet loss %,
        average/min/max latency, and RFC 3550-compliant jitter.
        """
        to = timeout if timeout is not None else self.timeout
        count = max(1, count)
        latencies: List[float] = []

        for i in range(count):
            rtt = self.ping_once(ip_address, timeout=to)
            if rtt is not None and rtt >= 0:
                latencies.append(round(rtt, 2))
            if i < count - 1 and interval > 0:
                time.sleep(interval)

        received = len(latencies)
        lost = count - received
        packet_loss = round((lost / count) * 100.0, 2)
        is_reachable = received > 0

        min_lat = None
        avg_lat = None
        max_lat = None
        jitter = None

        if is_reachable:
            min_lat = round(min(latencies), 2)
            max_lat = round(max(latencies), 2)
            avg_lat = round(sum(latencies) / received, 2)

            # RFC 3550 Interarrival Jitter approximation
            if received > 1:
                diffs = [abs(latencies[j] - latencies[j - 1]) for j in range(1, received)]
                jitter = round(sum(diffs) / len(diffs), 2)
            else:
                jitter = 0.0

        return ICMPResult(
            ip_address=ip_address,
            packets_sent=count,
            packets_received=received,
            packet_loss=packet_loss,
            latencies=latencies,
            min_latency=min_lat,
            avg_latency=avg_lat,
            max_latency=max_lat,
            jitter=jitter,
            is_reachable=is_reachable,
        )


class ICMPMonitoringEngine:
    """
    Orchestrates device ICMP polling, state transitions, metric recording,
    uptime recalculation, and automated incident alerting.
    """

    def __init__(self, checker: Optional[ICMPChecker] = None):
        self.checker = checker or ICMPChecker()

    def get_active_threshold(self):
        """Retrieves active threshold settings or provides fallback defaults."""
        from alerts.models import AlertThreshold

        threshold = AlertThreshold.objects.filter(is_active=True).first()
        if not threshold:
            # Fallback in-memory default threshold object
            class DefaultThreshold:
                high_latency_warning_ms = 100.0
                high_latency_critical_ms = 300.0
                packet_loss_warning_pct = 5.0
                packet_loss_critical_pct = 25.0
                consecutive_failures_for_offline = 3

            return DefaultThreshold()
        return threshold

    def calculate_device_uptime(self, device, window_hours: int = 24) -> float:
        """
        Calculates device availability percentage based on metrics recorded
        within the rolling time window (default: past 24 hours).
        """
        since = timezone.now() - timedelta(hours=window_hours)
        metrics_qs = device.metrics.filter(recorded_at__gte=since)
        total = metrics_qs.count()
        if total == 0:
            return 100.0 if device.status != "offline" else 0.0

        online_count = metrics_qs.exclude(status="offline").count()
        return round((online_count / total) * 100.0, 2)

    def check_device(
        self,
        device,
        packet_count: int = 4,
        timeout: float = 1.0,
    ):
        """
        Conducts an ICMP health check on a single device, updates its operational state,
        records a DeviceMetric, tracks consecutive failures, triggers/resolves alerts,
        and returns the created DeviceMetric.
        """
        from alerts.models import Alert
        from devices.models import Device
        from monitoring.models import DeviceMetric

        now = timezone.now()
        threshold = self.get_active_threshold()
        result = self.checker.ping_host(
            ip_address=device.ip_address,
            count=packet_count,
            timeout=timeout,
        )

        old_status = device.status

        if not result.is_reachable or result.packet_loss == 100.0:
            # Failure increment
            device.consecutive_failures += 1
            if device.consecutive_failures >= threshold.consecutive_failures_for_offline:
                new_status = Device.Status.OFFLINE
            else:
                # Intermittent or first/second failure: mark Warning to indicate flapping
                new_status = Device.Status.WARNING
        else:
            # Reachable: reset consecutive failures counter
            device.consecutive_failures = 0
            if (
                result.packet_loss >= threshold.packet_loss_warning_pct
                or (result.avg_latency and result.avg_latency >= threshold.high_latency_warning_ms)
            ):
                new_status = Device.Status.WARNING
            else:
                new_status = Device.Status.ONLINE

        # Update status change timestamp if transitioning
        if old_status != new_status:
            device.last_status_change = now
            device.status = new_status
            logger.info(
                "Device '%s' (%s) transitioned from %s to %s (failures: %d)",
                device.name,
                device.ip_address,
                old_status,
                new_status,
                device.consecutive_failures,
            )

        device.last_checked = now

        # Record Metric
        metric = DeviceMetric.objects.create(
            device=device,
            status=new_status,
            latency=result.avg_latency,
            packet_loss=result.packet_loss,
            jitter=result.jitter,
            recorded_at=now,
        )

        # Recalculate uptime
        device.uptime_percentage = self.calculate_device_uptime(device)
        device.save(
            update_fields=[
                "status",
                "last_status_change",
                "last_checked",
                "consecutive_failures",
                "uptime_percentage",
            ]
        )

        # Alert Generation & Self-Healing Logic
        self._evaluate_alerts(device, result, new_status, threshold, now)

        # Broadcast real-time device status & telemetry to WebSocket subscribers
        from monitoring.broadcaster import broadcast_device_metric
        broadcast_device_metric(device, metric, old_status=old_status)

        return metric

    def _evaluate_alerts(self, device, result: ICMPResult, new_status: str, threshold, now):
        """
        Manages the alert lifecycle: generates critical alerts on failure,
        warning/critical alerts on latency/packet loss degradation (with severity escalation),
        and auto-resolves active alerts when device recovers.
        """
        from alerts.engine import AlertEngine
        from alerts.models import Alert

        # 1. Device Offline Alert
        if new_status == "offline":
            AlertEngine.trigger_or_escalate_alert(
                device=device,
                alert_type=Alert.AlertType.DEVICE_OFFLINE,
                severity=Alert.Severity.CRITICAL,
                description=(
                    f"Device '{device.name}' ({device.ip_address}) is unreachable after "
                    f"{device.consecutive_failures} consecutive failed ICMP checks. 100% packet loss."
                ),
            )
        elif new_status == "online":
            AlertEngine.auto_resolve_alerts(device, Alert.AlertType.DEVICE_OFFLINE)

        # 2. High Latency Alert
        if result.avg_latency is not None and result.avg_latency >= threshold.high_latency_warning_ms:
            severity = (
                Alert.Severity.CRITICAL
                if result.avg_latency >= threshold.high_latency_critical_ms
                else Alert.Severity.WARNING
            )
            AlertEngine.trigger_or_escalate_alert(
                device=device,
                alert_type=Alert.AlertType.HIGH_LATENCY,
                severity=severity,
                description=(
                    f"High response time on '{device.name}' ({device.ip_address}): "
                    f"{result.avg_latency:.1f}ms exceeds threshold ({threshold.high_latency_warning_ms:.1f}ms)."
                ),
            )
        elif result.avg_latency is not None and result.avg_latency < threshold.high_latency_warning_ms:
            AlertEngine.auto_resolve_alerts(device, Alert.AlertType.HIGH_LATENCY)

        # 3. Packet Loss Alert
        if result.packet_loss >= threshold.packet_loss_warning_pct and result.packet_loss < 100.0:
            severity = (
                Alert.Severity.CRITICAL
                if result.packet_loss >= threshold.packet_loss_critical_pct
                else Alert.Severity.WARNING
            )
            AlertEngine.trigger_or_escalate_alert(
                device=device,
                alert_type=Alert.AlertType.PACKET_LOSS,
                severity=severity,
                description=(
                    f"Packet loss detected on '{device.name}' ({device.ip_address}): "
                    f"{result.packet_loss:.1f}% packet loss."
                ),
            )
        elif result.packet_loss < threshold.packet_loss_warning_pct:
            AlertEngine.auto_resolve_alerts(device, Alert.AlertType.PACKET_LOSS)

    def check_all_devices(
        self,
        device_ids: Optional[List[int]] = None,
        max_workers: int = 10,
        packet_count: int = 4,
        timeout: float = 1.0,
    ) -> dict:
        """
        Polls multiple devices concurrently using a ThreadPoolExecutor.
        Thread-safe: closes stale Django database connections per thread.
        Never blocks the Django server or web requests.
        """
        from devices.models import Device

        qs = Device.objects.filter(monitoring_enabled=True)
        if device_ids:
            qs = qs.filter(id__in=device_ids)

        devices = list(qs)
        if not devices:
            return {
                "total": 0,
                "online": 0,
                "offline": 0,
                "warning": 0,
                "metrics": [],
                "elapsed_seconds": 0.0,
            }

        start_time = time.time()
        metrics = []

        def _worker(dev):
            close_old_connections()
            try:
                metric = self.check_device(dev, packet_count=packet_count, timeout=timeout)
                return metric
            except Exception as e:
                logger.error("Error polling device '%s' (%s): %s", dev.name, dev.ip_address, e, exc_info=True)
                return None
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(devices)))) as executor:
            futures = {executor.submit(_worker, d): d for d in devices}
            for fut in as_completed(futures):
                metric = fut.result()
                if metric:
                    metrics.append(metric)

        elapsed = round(time.time() - start_time, 2)
        online = sum(1 for m in metrics if m.status == "online")
        offline = sum(1 for m in metrics if m.status == "offline")
        warning = sum(1 for m in metrics if m.status == "warning")

        return {
            "total": len(metrics),
            "online": online,
            "offline": offline,
            "warning": warning,
            "metrics": metrics,
            "elapsed_seconds": elapsed,
        }
