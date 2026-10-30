"""
Django Management Command: run_snmp_poll

Interrogates SNMP-enabled network devices via SNMPv2c or SNMPv3.
Collects system metadata (sysDescr, sysUptime, sysName), interface operational states,
and calculates bandwidth rates (bps) from interface counters.

Usage examples:
    python manage.py run_snmp_poll
    python manage.py run_snmp_poll --device-id 1
    python manage.py run_snmp_poll --workers 10 --timeout 2.5
    python manage.py run_snmp_poll --continuous --interval 60
"""

import time
from django.core.management.base import BaseCommand
from django.utils import timezone

from devices.models import Device
from monitoring.snmp import SNMPMonitoringEngine


class Command(BaseCommand):
    help = "Conducts SNMP telemetry collection and interface bandwidth calculation"

    def add_arguments(self, parser):
        parser.add_argument(
            "--device-id",
            type=int,
            help="Poll only a specific device by primary key ID",
        )
        parser.add_argument(
            "--device-name",
            type=str,
            help="Poll only a specific device by hostname/name",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=5,
            help="Number of concurrent worker threads for multi-device SNMP polling (default: 5)",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=2.0,
            help="SNMP timeout in seconds (default: 2.0s)",
        )
        parser.add_argument(
            "--continuous",
            action="store_true",
            help="Run in continuous polling loop until interrupted",
        )
        parser.add_argument(
            "--interval",
            type=int,
            default=60,
            help="Interval in seconds between polling cycles in continuous mode (default: 60s)",
        )

    def handle(self, *args, **options):
        engine = SNMPMonitoringEngine()
        device_id = options.get("device_id")
        device_name = options.get("device_name")
        workers = options.get("workers", 5)
        timeout = options.get("timeout", 2.0)
        continuous = options.get("continuous", False)
        interval = options.get("interval", 60)

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                f"[NetPulse] Starting SNMP Telemetry Engine (Workers: {workers}, Timeout: {timeout}s)"
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
                    self.stderr.write(self.style.ERROR("Device not found."))
                    return

                if not device.snmp_enabled:
                    self.stdout.write(
                        self.style.WARNING(f"Device '{device.name}' does not have SNMP enabled.")
                    )
                    return

                self.stdout.write(f"Interrogating device: {device.name} ({device.ip_address}) via {device.snmp_version.upper()}...")
                data = engine.poll_device(device, timeout=timeout)
                if data.is_successful:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f" -> SUCCESS | System: {data.sys_description[:60]}... | Uptime: {data.sys_uptime} | "
                            f"Interfaces Discovered: {len(data.interfaces)}"
                        )
                    )
                    for iface in data.interfaces:
                        self.stdout.write(
                            f"    [{iface.index}] {iface.name}: {iface.oper_status.upper()} "
                            f"(In: {iface.in_octets} octets, Out: {iface.out_octets} octets)"
                        )
                else:
                    self.stdout.write(
                        self.style.ERROR(f" -> FAILED | Error: {data.error_message}")
                    )
            else:
                summary = engine.poll_all_snmp_devices(
                    max_workers=workers,
                    timeout=timeout,
                )
                self.stdout.write(
                    f"[{timezone.now():%H:%M:%S}] Polled {summary['total']} SNMP devices in {summary['elapsed_seconds']}s -> "
                    + self.style.SUCCESS(f"{summary['successful']} Successful")
                    + " | "
                    + self.style.ERROR(f"{summary['failed']} Failed")
                )

        if continuous:
            self.stdout.write(self.style.NOTICE(f"Running continuously every {interval} seconds. Press Ctrl+C to stop."))
            try:
                while True:
                    run_cycle()
                    time.sleep(interval)
            except KeyboardInterrupt:
                self.stdout.write(self.style.NOTICE("\nSNMP polling loop stopped by user."))
        else:
            run_cycle()
            self.stdout.write(self.style.SUCCESS("[NetPulse] SNMP polling cycle completed."))
