"""
Django Management Command: run_icmp_check

Executes ICMP health checks across network devices registered in NetPulse.
Measures latency, packet loss, and jitter; tracks consecutive failures,
updates device statuses, and logs DeviceMetric records to PostgreSQL.

Usage examples:
    python manage.py run_icmp_check
    python manage.py run_icmp_check --device-id 1 --count 5
    python manage.py run_icmp_check --workers 20 --timeout 1.5
    python manage.py run_icmp_check --continuous --interval 30
"""

import sys
import time
from django.core.management.base import BaseCommand
from django.utils import timezone

from devices.models import Device
from monitoring.icmp import ICMPMonitoringEngine


class Command(BaseCommand):
    help = "Conducts ICMP availability and performance checks on monitored network devices"

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-id",
            type=int,
            help="Check only a specific device by primary key ID",
        )
        parser.add_argument(
            "--device-name",
            type=str,
            help="Check only a specific device by hostname/name",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=10,
            help="Number of concurrent worker threads for multi-device polling (default: 10)",
        )
        parser.add_argument(
            "--count",
            type=int,
            default=4,
            help="Number of ICMP echo requests per check (default: 4)",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=1.0,
            help="Timeout per echo request in seconds (default: 1.0s)",
        )
        parser.add_argument(
            "--continuous",
            action="store_true",
            help="Run in continuous polling loop until interrupted",
        )
        parser.add_argument(
            "--interval",
            type=int,
            default=30,
            help="Interval in seconds between polling cycles in continuous mode (default: 30s)",
        )

    def handle(self, *args, **options):
        engine = ICMPMonitoringEngine()
        device_id = options.get("device_id")
        device_name = options.get("device_name")
        workers = options.get("workers", 10)
        count = options.get("count", 4)
        timeout = options.get("timeout", 1.0)
        continuous = options.get("continuous", False)
        interval = options.get("interval", 30)

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                f"[NetPulse] Starting ICMP Monitoring Engine (Workers: {workers}, Packets: {count}, Timeout: {timeout}s)"
            )
        )

        def run_cycle():
            if device_id or device_name:
                try:
                    if device_id:
                        device = Device.objects.get(id=device_id)
                    else:
                        device = Device.objects.get(name=device_name)
                except Device.DoesNotExist:
                    self.stderr.write(self.style.ERROR(f"Device not found."))
                    return

                self.stdout.write(f"Checking device: {device.name} ({device.ip_address})...")
                metric = engine.check_device(device, packet_count=count, timeout=timeout)
                status_color = (
                    self.style.SUCCESS
                    if metric.status == "online"
                    else (self.style.WARNING if metric.status == "warning" else self.style.ERROR)
                )
                self.stdout.write(
                    status_color(
                        f" -> Status: {metric.status.upper()} | Latency: {metric.latency or 0.0:.1f}ms | "
                        f"Loss: {metric.packet_loss:.1f}% | Jitter: {metric.jitter or 0.0:.1f}ms | "
                        f"Consecutive Failures: {device.consecutive_failures}"
                    )
                )
            else:
                summary = engine.check_all_devices(
                    max_workers=workers,
                    packet_count=count,
                    timeout=timeout,
                )
                self.stdout.write(
                    f"[{timezone.now():%H:%M:%S}] Checked {summary['total']} devices in {summary['elapsed_seconds']}s -> "
                    + self.style.SUCCESS(f"{summary['online']} Online")
                    + " | "
                    + self.style.WARNING(f"{summary['warning']} Warning")
                    + " | "
                    + self.style.ERROR(f"{summary['offline']} Offline")
                )

        if continuous:
            self.stdout.write(self.style.NOTICE(f"Running continuously every {interval} seconds. Press Ctrl+C to stop."))
            try:
                while True:
                    run_cycle()
                    time.sleep(interval)
            except KeyboardInterrupt:
                self.stdout.write(self.style.NOTICE("\nMonitoring loop stopped by user."))
        else:
            run_cycle()
            self.stdout.write(self.style.SUCCESS("[NetPulse] ICMP check completed successfully."))
