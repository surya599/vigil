"""
Management command to seed realistic NOC demonstration data idempotently:
- RBAC demo users (admin, operator, viewer)
- Enterprise network devices across Core, Distribution, Access, and Edge tiers
- SNMP NetworkInterface records & InterfaceMetric bandwidth telemetry
- DeviceMetric ICMP latency/jitter/packet-loss time-series
- NetworkTrafficSnapshot & DeviceDailySummary SLA rollups
- Global & device-specific AlertThreshold rules and sample Alert incidents
- NetworkConnection topology links
"""
from datetime import timedelta
from decimal import Decimal
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone

from devices.models import Device, DiscoveryScan, DiscoveredDevice, NetworkChangeEvent
from monitoring.models import DeviceMetric, NetworkInterface, InterfaceMetric
from analytics.models import NetworkTrafficSnapshot, DeviceDailySummary
from alerts.models import Alert, AlertThreshold
from topology.models import NetworkConnection


class Command(BaseCommand):
    help = "Seed realistic NetPulse NOC demonstration data idempotently."

    def handle(self, *args, **options):
        User = get_user_model()
        now = timezone.now()

        # 1. Seed Demo RBAC Accounts
        admin_user, created = User.objects.get_or_create(
            username="noc_admin",
            defaults={
                "email": "admin@netpulse.local",
                "is_staff": True,
                "is_superuser": True,
            },
        )
        if created:
            admin_user.set_password("NetPulseAdmin!2026")
            admin_user.save()
        admin_user.profile.role = "admin"
        admin_user.profile.department = "NOC Architecture"
        admin_user.profile.save()

        operator_user, created = User.objects.get_or_create(
            username="noc_operator",
            defaults={
                "email": "operator@netpulse.local",
            },
        )
        if created:
            operator_user.set_password("NetPulseOp!2026")
            operator_user.save()
        operator_user.profile.role = "operator"
        operator_user.profile.department = "Tier-2 NOC Operations"
        operator_user.profile.save()

        viewer_user, created = User.objects.get_or_create(
            username="noc_viewer",
            defaults={
                "email": "viewer@netpulse.local",
            },
        )
        if created:
            viewer_user.set_password("NetPulseView!2026")
            viewer_user.save()
        viewer_user.profile.role = "viewer"
        viewer_user.profile.department = "Executive Dashboard"
        viewer_user.profile.save()

        # 2. Seed Network Devices across Core, Distribution, Access, and Edge tiers
        device_specs = [
            {
                "name": "Core-Router-01",
                "ip_address": "10.100.0.1",
                "mac_address": "00:1A:2B:3C:4D:01",
                "device_type": Device.DeviceType.ROUTER,
                "location": "DC-1 Core Rack A1",
                "status": Device.Status.ONLINE,
                "uptime_percentage": Decimal("99.98"),
                "snmp_enabled": True,
                "sys_description": "Cisco IOS XE Software, ASR1002-HX Core Router",
                "sys_uptime": "142 days, 08:14:22",
                "latency_ms": 2.4,
                "loss_pct": 0.0,
            },
            {
                "name": "Edge-Firewall-01",
                "ip_address": "10.100.0.2",
                "mac_address": "00:1A:2B:3C:4D:02",
                "device_type": Device.DeviceType.FIREWALL,
                "location": "DC-1 DMZ Perimeter",
                "status": Device.Status.ONLINE,
                "uptime_percentage": Decimal("99.95"),
                "snmp_enabled": True,
                "sys_description": "Palo Alto Networks PA-5220 Next-Gen Firewall",
                "sys_uptime": "98 days, 19:40:10",
                "latency_ms": 3.8,
                "loss_pct": 0.0,
            },
            {
                "name": "Dist-Switch-01",
                "ip_address": "10.100.1.10",
                "mac_address": "00:1A:2B:3C:4D:03",
                "device_type": Device.DeviceType.SWITCH,
                "location": "DC-1 Aggregation Row B",
                "status": Device.Status.ONLINE,
                "uptime_percentage": Decimal("99.90"),
                "snmp_enabled": True,
                "sys_description": "Arista Networks EOS 7280SR-48C6 L3 Switch",
                "sys_uptime": "64 days, 11:05:49",
                "latency_ms": 5.1,
                "loss_pct": 0.0,
            },
            {
                "name": "Dist-Switch-02",
                "ip_address": "10.100.1.11",
                "mac_address": "00:1A:2B:3C:4D:04",
                "device_type": Device.DeviceType.SWITCH,
                "location": "DC-1 Aggregation Row C",
                "status": Device.Status.WARNING,
                "uptime_percentage": Decimal("97.45"),
                "snmp_enabled": True,
                "sys_description": "Arista Networks EOS 7050X3 Distribution Switch",
                "sys_uptime": "19 days, 04:22:15",
                "latency_ms": 185.0,
                "loss_pct": 12.5,
            },
            {
                "name": "Prod-App-Server-01",
                "ip_address": "10.100.2.20",
                "mac_address": "00:1A:2B:3C:4D:05",
                "device_type": Device.DeviceType.SERVER,
                "location": "DC-1 Compute Pod 1",
                "status": Device.Status.ONLINE,
                "uptime_percentage": Decimal("99.85"),
                "snmp_enabled": True,
                "sys_description": "Linux prod-app-01 6.8.0-enterprise x86_64",
                "sys_uptime": "45 days, 16:30:00",
                "latency_ms": 8.2,
                "loss_pct": 0.0,
            },
            {
                "name": "Replica-DB-Server-02",
                "ip_address": "10.100.2.21",
                "mac_address": "00:1A:2B:3C:4D:06",
                "device_type": Device.DeviceType.SERVER,
                "location": "DC-1 Storage Pod 2",
                "status": Device.Status.OFFLINE,
                "uptime_percentage": Decimal("92.10"),
                "consecutive_failures": 4,
                "snmp_enabled": True,
                "sys_description": "PostgreSQL 18 HA Replica Cluster Node",
                "sys_uptime": "0 days, 00:00:00",
                "latency_ms": None,
                "loss_pct": 100.0,
            },
            {
                "name": "Campus-WiFi-AP-01",
                "ip_address": "10.100.3.50",
                "mac_address": "00:1A:2B:3C:4D:07",
                "device_type": Device.DeviceType.ACCESS_POINT,
                "location": "HQ Floor 3 East Wing",
                "status": Device.Status.ONLINE,
                "uptime_percentage": Decimal("99.50"),
                "snmp_enabled": False,
                "sys_description": "Cisco Catalyst 9130AXI Wi-Fi 6E Access Point",
                "sys_uptime": "31 days, 02:18:04",
                "latency_ms": 14.6,
                "loss_pct": 0.0,
            },
        ]

        devices_by_name = {}
        for spec in device_specs:
            latency_ms = spec.pop("latency_ms")
            loss_pct = spec.pop("loss_pct")
            dev, _ = Device.objects.update_or_create(
                name=spec["name"],
                defaults={
                    **spec,
                    "last_checked": now,
                    "last_status_change": now - timedelta(hours=2),
                },
            )
            devices_by_name[dev.name] = dev

            # Create historical DeviceMetric points over the past 6 hours
            if not dev.metrics.exists():
                for step in range(6, -1, -1):
                    ts = now - timedelta(minutes=step * 30)
                    DeviceMetric.objects.create(
                        device=dev,
                        status=dev.status,
                        latency=latency_ms if latency_ms is not None else None,
                        packet_loss=loss_pct,
                        jitter=1.2 if latency_ms else None,
                        recorded_at=ts,
                    )

            # Create NetworkInterface & InterfaceMetric records
            iface, _ = NetworkInterface.objects.update_or_create(
                device=dev,
                interface_name="GigabitEthernet0/0/1",
                defaults={
                    "interface_index": 1,
                    "ip_address": dev.ip_address,
                    "speed_bps": 10_000_000_000 if dev.device_type in ("router", "switch") else 1_000_000_000,
                    "operational_status": (
                        NetworkInterface.OperationalStatus.DOWN
                        if dev.status == Device.Status.OFFLINE
                        else NetworkInterface.OperationalStatus.UP
                    ),
                    "admin_status": NetworkInterface.AdminStatus.UP,
                    "description": f"Primary Uplink ({dev.name})",
                },
            )
            if not iface.metrics.exists():
                base_in = 420_000_000.0 if dev.status != Device.Status.OFFLINE else 0.0
                base_out = 285_000_000.0 if dev.status != Device.Status.OFFLINE else 0.0
                for step in range(4, -1, -1):
                    InterfaceMetric.objects.create(
                        interface=iface,
                        incoming_bytes=10_000_000_000 + (4 - step) * 50_000_000,
                        outgoing_bytes=8_000_000_000 + (4 - step) * 35_000_000,
                        incoming_bps=base_in + (step * 5_000_000.0 if base_in else 0.0),
                        outgoing_bps=base_out + (step * 3_500_000.0 if base_out else 0.0),
                        recorded_at=now - timedelta(minutes=step * 15),
                    )

            # Seed Daily SLA Summary
            DeviceDailySummary.objects.update_or_create(
                device=dev,
                date=now.date(),
                defaults={
                    "uptime_seconds": int(float(dev.uptime_percentage) * 864),
                    "downtime_seconds": max(0, 86400 - int(float(dev.uptime_percentage) * 864)),
                    "uptime_percentage": dev.uptime_percentage,
                    "avg_latency": latency_ms or 0.0,
                    "max_latency": (latency_ms or 0.0) * 1.35,
                    "avg_packet_loss": loss_pct,
                    "total_alerts_count": 1 if dev.status != Device.Status.ONLINE else 0,
                },
            )

        # 3. Seed NetworkTrafficSnapshot history
        if NetworkTrafficSnapshot.objects.count() < 6:
            for step in range(6, -1, -1):
                NetworkTrafficSnapshot.objects.create(
                    recorded_at=now - timedelta(minutes=step * 15),
                    total_devices=len(devices_by_name),
                    online_devices=5,
                    warning_devices=1,
                    offline_devices=1,
                    average_latency=36.5,
                    average_packet_loss=2.1,
                    total_incoming_bps=2_450_000_000.0,
                    total_outgoing_bps=1_680_000_000.0,
                )

        # 4. Seed Global AlertThreshold & Active/Acknowledged Alerts
        AlertThreshold.objects.get_or_create(
            name="Default Global Thresholds",
            defaults={
                "high_latency_warning_ms": 100.0,
                "high_latency_critical_ms": 300.0,
                "packet_loss_warning_pct": 5.0,
                "packet_loss_critical_pct": 25.0,
                "consecutive_failures_for_offline": 3,
                "is_active": True,
            },
        )

        offline_dev = devices_by_name["Replica-DB-Server-02"]
        Alert.objects.get_or_create(
            device=offline_dev,
            alert_type=Alert.AlertType.DEVICE_OFFLINE,
            is_resolved=False,
            defaults={
                "severity": Alert.Severity.CRITICAL,
                "description": f"{offline_dev.name} ({offline_dev.ip_address}) failed 4 consecutive ICMP checks.",
            },
        )

        warn_dev = devices_by_name["Dist-Switch-02"]
        Alert.objects.get_or_create(
            device=warn_dev,
            alert_type=Alert.AlertType.HIGH_LATENCY,
            is_resolved=False,
            defaults={
                "severity": Alert.Severity.WARNING,
                "description": f"Measured RTT 185.0 ms exceeds warning threshold 100.0 ms on {warn_dev.name}.",
                "is_acknowledged": True,
                "acknowledged_by": operator_user,
                "acknowledged_at": now - timedelta(minutes=25),
            },
        )

        # 5. Seed Network Topology Links
        topology_pairs = [
            ("Edge-Firewall-01", "Core-Router-01", NetworkConnection.ConnectionType.FIBER, "40 Gbps"),
            ("Core-Router-01", "Dist-Switch-01", NetworkConnection.ConnectionType.FIBER, "40 Gbps"),
            ("Core-Router-01", "Dist-Switch-02", NetworkConnection.ConnectionType.FIBER, "40 Gbps"),
            ("Dist-Switch-01", "Prod-App-Server-01", NetworkConnection.ConnectionType.ETHERNET, "10 Gbps"),
            ("Dist-Switch-02", "Replica-DB-Server-02", NetworkConnection.ConnectionType.ETHERNET, "10 Gbps"),
            ("Dist-Switch-01", "Campus-WiFi-AP-01", NetworkConnection.ConnectionType.WIRELESS, "2.5 Gbps"),
        ]
        for src_name, dst_name, conn_type, link_speed in topology_pairs:
            src = devices_by_name[src_name]
            dst = devices_by_name[dst_name]
            if src.status == Device.Status.OFFLINE or dst.status == Device.Status.OFFLINE:
                link_status = NetworkConnection.Status.DOWN
            elif src.status == Device.Status.WARNING or dst.status == Device.Status.WARNING:
                link_status = NetworkConnection.Status.DEGRADED
            else:
                link_status = NetworkConnection.Status.ACTIVE

            NetworkConnection.objects.update_or_create(
                source_device=src,
                destination_device=dst,
                defaults={
                    "connection_type": conn_type,
                    "link_speed": link_speed,
                    "status": link_status,
                    "is_discovered": True,
                    "discovery_method": NetworkConnection.DiscoveryMethod.LLDP if conn_type == NetworkConnection.ConnectionType.FIBER else NetworkConnection.DiscoveryMethod.SUBNET_INFERRED,
                    "is_confirmed": conn_type == NetworkConnection.ConnectionType.FIBER,
                },
            )

        # 6. Seed VIGIL Discovery Scan, Discovered Inventory & Change Events
        scan, _ = DiscoveryScan.objects.get_or_create(
            target_cidr="10.100.0.0/24",
            status=DiscoveryScan.Status.COMPLETED,
            defaults={
                "interface_name": "Ethernet0",
                "started_by": admin_user,
                "started_at": now - timedelta(minutes=20),
                "completed_at": now - timedelta(minutes=19),
                "duration_seconds": 12.4,
                "progress_pct": 100,
                "total_hosts_scanned": 254,
                "discovered_count": 9,
                "new_devices_count": 2,
            },
        )

        disc_unmonitored, _ = DiscoveredDevice.objects.update_or_create(
            ip_address="10.100.4.88",
            defaults={
                "mac_address": "30:05:5C:10:20:30",
                "hostname": "hp-laserjet-fl2.corp.local",
                "manufacturer": "Brother Industries",
                "device_type": Device.DeviceType.PRINTER,
                "discovery_methods": "arp,icmp,dns,port",
                "is_reachable": True,
                "confidence_score": 88,
                "open_ports": "80,443,631,9100",
                "trust_status": DiscoveredDevice.TrustStatus.TRUSTED,
                "last_scan": scan,
            },
        )

        disc_unknown, _ = DiscoveredDevice.objects.update_or_create(
            ip_address="10.100.4.199",
            defaults={
                "mac_address": "DE:AD:BE:EF:11:22",
                "hostname": "",
                "manufacturer": "",
                "device_type": Device.DeviceType.UNKNOWN,
                "discovery_methods": "arp",
                "is_reachable": True,
                "confidence_score": 20,
                "open_ports": "",
                "trust_status": DiscoveredDevice.TrustStatus.UNKNOWN,
                "last_scan": scan,
            },
        )

        NetworkChangeEvent.objects.get_or_create(
            discovered_device=disc_unknown,
            event_type=NetworkChangeEvent.EventType.NEW_DEVICE,
            defaults={
                "severity": NetworkChangeEvent.Severity.INFO,
                "previous_value": "",
                "new_value": "10.100.4.199",
                "description": "Newly discovered unknown device at 10.100.4.199 via ARP scan.",
            },
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully seeded VIGIL NOC demo dataset: "
                f"{len(devices_by_name)} monitored devices, {DiscoveredDevice.objects.count()} discovered devices, "
                f"{NetworkConnection.objects.count()} topology links, and {Alert.objects.count()} incident alerts."
            )
        )
