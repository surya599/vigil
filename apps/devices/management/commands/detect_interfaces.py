"""
VIGIL Phase 2 Management Command: detect_interfaces
Detects active and available host network interfaces, IPv4 addresses, subnet masks,
calculated CIDR ranges, MAC addresses, and default gateways.
"""
from django.core.management.base import BaseCommand
from devices.network_interfaces import NetworkInterfaceDetector


class Command(BaseCommand):
    help = "Detect host network interfaces, IPv4 addresses, subnet masks, gateways, and CIDR ranges."

    def add_arguments(self, parser):
        parser.add_argument(
            "--include-loopback",
            action="store_true",
            help="Include loopback interfaces (127.0.0.1) in output.",
        )
        parser.add_argument(
            "--active-only",
            action="store_true",
            help="Only display operationally UP network interfaces.",
        )

    def handle(self, *args, **options):
        include_loopback = options["include_loopback"]
        active_only = options["active_only"]

        interfaces = NetworkInterfaceDetector.detect_interfaces(
            include_loopback=include_loopback,
            active_only=active_only,
        )
        self.stdout.write(
            self.style.SUCCESS(f"VIGIL Interface Detector — Found {len(interfaces)} IPv4 interface(s):")
        )
        for idx, iface in enumerate(interfaces, start=1):
            primary_tag = " [PRIMARY]" if iface.is_primary else ""
            status_tag = "UP" if iface.is_active else "DOWN"
            self.stdout.write(
                f"  [{idx}] {iface.name}{primary_tag} ({status_tag})\n"
                f"      Local IP   : {iface.ipv4_address}\n"
                f"      Subnet Mask: {iface.subnet_mask}\n"
                f"      Gateway    : {iface.default_gateway or 'N/A'}\n"
                f"      Network CIDR: {iface.network_cidr} ({iface.usable_hosts_count} usable hosts)\n"
                f"      MAC Address: {iface.mac_address or 'N/A'}"
            )
