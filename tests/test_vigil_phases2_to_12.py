"""
Comprehensive Automated Test Suite for VIGIL Phases 2 through 12:
- Phase 2: Automatic Network Interface & Subnet CIDR Detection + RFC 1918 Scope Guard
- Phase 3: Multi-Technique Network Discovery Engine (ARP, ICMP, Reverse DNS, Port Probe)
- Phase 4: Device Identification, Confidence Scoring & MAC OUI Vendor Lookup
- Phase 5: Network Discovery Dashboard (/discovery/), Live Scan Progress & Deduplicated Onboarding
- Phase 6: Network Inventory Change Detection (New, Disappeared, Returned, IP/MAC/Hostname Changes) & Trust Workflow
- Phase 7: Real-Time Dashboard Telemetry (Discovered Inventory, Unknown Count, CPU/Memory)
- Phase 8: Advanced SNMP Telemetry (CPU, Memory, Errors, Discards, sysObjectID)
- Phase 9: Confirmed (LLDP/CDP/Interface/Manual) vs. Inferred (Shared Subnet) Topology Links
- Phase 10: CPU & Memory Resource Alert Evaluation, Escalation & Auto-Resolution
- Phase 11: Advanced Network Utilities (DNS Check, TCP Port Checker, Traceroute Parser, SLA Uptime Report)
- Phase 12: Security AuditLog Trail & Authorized Scan Scope Hardening
"""
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import AuditLog
from alerts.engine import AlertEngine
from alerts.models import Alert, AlertThreshold
from devices.discovery import DiscoveredHostRecord, NetworkDiscoveryEngine
from devices.identification import DeviceIdentificationEngine
from devices.models import Device, DiscoveredDevice, DiscoveryScan, NetworkChangeEvent
from devices.network_interfaces import NetworkInterfaceDetector
from monitoring.models import NetworkInterface
from monitoring.utilities import NetworkUtilitiesEngine
from topology.engine import TopologyEngine
from topology.models import NetworkConnection

User = get_user_model()


@pytest.fixture
def operator_client(db):
    user = User.objects.create_user(username="vigil_op", password="Password123!")
    user.profile.role = "operator"
    user.profile.save()
    client = APIClient()
    client.force_authenticate(user=user)
    client.force_login(user)
    return client, user


@pytest.fixture
def viewer_client(db):
    user = User.objects.create_user(username="vigil_viewer", password="Password123!")
    user.profile.role = "viewer"
    user.profile.save()
    client = APIClient()
    client.force_authenticate(user=user)
    client.force_login(user)
    return client, user


# ============================================================================
# PHASE 2: NETWORK INTERFACE DETECTION & AUTHORIZED CIDR VALIDATION
# ============================================================================
@pytest.mark.django_db
class TestVigilPhase2InterfaceDetection:
    def test_calculate_network_range_exact_spec(self):
        """Verifies Local IP 10.0.114.20 + Mask 255.255.255.0 -> 10.0.114.0/24."""
        calc = NetworkInterfaceDetector.calculate_network_range("10.0.114.20", "255.255.255.0")
        assert calc["network_cidr"] == "10.0.114.0/24"
        assert calc["prefix_len"] == 24
        assert calc["usable_hosts_count"] == 254

    def test_detect_interfaces_live_system(self):
        """Detects active OS network interfaces with IPv4, netmask, and calculated CIDR."""
        interfaces = NetworkInterfaceDetector.detect_interfaces(include_loopback=True)
        assert isinstance(interfaces, list)
        assert len(interfaces) >= 1
        first = interfaces[0].to_dict()
        assert "name" in first
        assert "ipv4_address" in first
        assert "subnet_mask" in first
        assert "network_cidr" in first
        assert "mac_address" in first

    def test_validate_authorized_cidr_blocks_public_ranges(self):
        """Strictly blocks public IP ranges and oversized subnets while allowing RFC 1918."""
        ok, msg, info = NetworkInterfaceDetector.validate_authorized_cidr("192.168.1.0/24")
        assert ok is True
        assert info["network_cidr"] == "192.168.1.0/24"
        assert info["usable_hosts_count"] == 254

        pub_ok, pub_msg, _ = NetworkInterfaceDetector.validate_authorized_cidr("8.8.8.0/24")
        assert pub_ok is False
        assert "Unauthorized" in pub_msg

        over_ok, over_msg, _ = NetworkInterfaceDetector.validate_authorized_cidr("10.0.0.0/16")
        assert over_ok is False
        assert "exceeding the maximum scan limit" in over_msg

    def test_detect_interfaces_management_command_and_apis(self, operator_client):
        client, _ = operator_client
        out = StringIO()
        call_command("detect_interfaces", "--include-loopback", stdout=out)
        assert "CIDR" in out.getvalue() or "127.0.0.1" in out.getvalue()

        res = client.get("/api/discovery/interfaces/?include_loopback=true")
        assert res.status_code == 200
        assert "interfaces" in res.data

        val_ok = client.post("/api/discovery/validate-cidr/", {"cidr": "10.0.114.0/24"}, format="json")
        assert val_ok.status_code == 200
        assert val_ok.data["valid"] is True

        val_bad = client.post("/api/discovery/validate-cidr/", {"cidr": "1.1.1.0/24"}, format="json")
        assert val_bad.status_code == 400
        assert val_bad.data["valid"] is False


# ============================================================================
# PHASE 3 & 4: MULTI-TECHNIQUE DISCOVERY & DEVICE IDENTIFICATION ENGINE
# ============================================================================
@pytest.mark.django_db
class TestVigilPhase3And4DiscoveryAndIdentification:
    def test_mac_vendor_lookup_and_device_classification(self):
        """Verifies MAC OUI vendor lookup and multi-signal confidence classification."""
        vendor, hint = DeviceIdentificationEngine.lookup_mac_vendor("00:1A:2B:AA:BB:CC")
        assert vendor == "Cisco Systems"
        assert hint == "router"

        p_vendor, p_hint = DeviceIdentificationEngine.lookup_mac_vendor("30:05:5C:11:22:33")
        assert p_vendor == "Brother Industries"
        assert p_hint == "printer"

        assert DeviceIdentificationEngine.lookup_mac_vendor("") == ("", None)

        # 1. Router via SNMP sysDescr + Gateway IP
        r_info = DeviceIdentificationEngine.identify_device(
            ip_address="10.0.114.1",
            mac_address="00:1A:2B:10:20:30",
            hostname="core-rtr-01.corp.local",
            sys_description="Cisco IOS XE Software, ASR1000 Router",
            sys_object_id="1.3.6.1.4.1.9.1.123",
            is_gateway=True,
        )
        assert r_info.device_type == Device.DeviceType.ROUTER
        assert r_info.manufacturer == "Cisco Systems"
        assert r_info.confidence_score >= 85

        # 2. Printer via Port 9100 + MAC OUI
        p_info = DeviceIdentificationEngine.identify_device(
            ip_address="10.0.114.45",
            mac_address="30:05:5C:AA:BB:CC",
            hostname="brother-laserjet-fl1",
            open_ports=[80, 631, 9100],
        )
        assert p_info.device_type == Device.DeviceType.PRINTER
        assert p_info.confidence_score >= 70

        # 3. Unknown device does not fabricate manufacturer or type
        u_info = DeviceIdentificationEngine.identify_device(
            ip_address="10.0.114.222",
            mac_address="",
            hostname="",
            open_ports=[],
        )
        assert u_info.device_type == Device.DeviceType.UNKNOWN
        assert u_info.manufacturer == ""
        assert u_info.confidence_score <= 35

    def test_arp_discovered_device_not_discarded_when_icmp_fails(self):
        """
        Requirement 3.2: ICMP failure must not automatically classify a device as nonexistent.
        Hosts present in ARP table must be discovered even when ICMP ping fails.
        """
        engine = NetworkDiscoveryEngine(enable_port_probe=False)
        with patch.object(NetworkDiscoveryEngine, "try_scapy_arp_scan", return_value={
            "10.0.114.50": "B8:27:EB:11:22:33"
        }), patch.object(NetworkDiscoveryEngine, "read_os_arp_table", return_value={}), \
             patch.object(NetworkDiscoveryEngine, "_probe_single_host", return_value=(
                 "10.0.114.50", False, None, []
             )):
            records = engine.scan_subnet("10.0.114.48/30", host_ips_override=["10.0.114.50"])
            discovered_ips = [r.ip_address for r in records]
            assert "10.0.114.50" in discovered_ips
            host = next(r for r in records if r.ip_address == "10.0.114.50")
            assert host.is_reachable is True
            assert "arp" in host.discovery_methods
            assert host.manufacturer == "Raspberry Pi Foundation"


# ============================================================================
# PHASE 5 & 6: INVENTORY CHANGE DETECTION, TRUST WORKFLOW & REGISTRATION
# ============================================================================
@pytest.mark.django_db
class TestVigilPhase5And6InventoryAndChangeDetection:
    def test_network_inventory_change_detection_lifecycle(self):
        """
        Tests full change detection lifecycle:
        1. Newly discovered device -> NEW_DEVICE event
        2. Disappearing device -> DEVICE_DISAPPEARED event
        3. Returning device -> DEVICE_RETURNED event
        4. IP address change for known MAC -> IP_CHANGED event
        5. Hostname change -> HOSTNAME_CHANGED event
        """
        scan1 = DiscoveryScan.objects.create(target_cidr="10.20.30.0/24", status="running")
        batch1 = [
            DiscoveredHostRecord(
                ip_address="10.20.30.10",
                mac_address="00:50:56:AA:BB:01",
                hostname="vm-web-01.local",
                manufacturer="VMware, Inc.",
                device_type=Device.DeviceType.SERVER,
                confidence_score=80,
                discovery_methods=["arp", "icmp"],
                is_reachable=True,
                open_ports=[22, 80],
                subnet_cidr="10.20.30.0/24",
            )
        ]
        res1 = NetworkDiscoveryEngine.sync_discovered_inventory(batch1, "10.20.30.0/24", scan_obj=scan1)
        assert res1["new_devices"] == 1
        assert NetworkChangeEvent.objects.filter(
            event_type=NetworkChangeEvent.EventType.NEW_DEVICE,
            new_value="10.20.30.10",
        ).exists()

        # Scan 2: Device disappears (empty scan result on same subnet)
        scan2 = DiscoveryScan.objects.create(target_cidr="10.20.30.0/24", status="running")
        NetworkDiscoveryEngine.sync_discovered_inventory([], "10.20.30.0/24", scan_obj=scan2)
        disc = DiscoveredDevice.objects.get(mac_address="00:50:56:AA:BB:01")
        assert disc.is_reachable is False
        assert NetworkChangeEvent.objects.filter(
            event_type=NetworkChangeEvent.EventType.DEVICE_DISAPPEARED,
            discovered_device=disc,
        ).exists()

        # Scan 3: Device returns at same IP with updated hostname -> DEVICE_RETURNED + HOSTNAME_CHANGED
        scan3 = DiscoveryScan.objects.create(target_cidr="10.20.30.0/24", status="running")
        batch3 = [
            DiscoveredHostRecord(
                ip_address="10.20.30.10",
                mac_address="00:50:56:AA:BB:01",
                hostname="vm-web-01-prod.local",
                manufacturer="VMware, Inc.",
                device_type=Device.DeviceType.SERVER,
                confidence_score=85,
                discovery_methods=["arp", "icmp"],
                is_reachable=True,
                open_ports=[22, 443],
                subnet_cidr="10.20.30.0/24",
            )
        ]
        NetworkDiscoveryEngine.sync_discovered_inventory(batch3, "10.20.30.0/24", scan_obj=scan3)
        disc.refresh_from_db()
        assert disc.is_reachable is True
        assert NetworkChangeEvent.objects.filter(
            event_type=NetworkChangeEvent.EventType.DEVICE_RETURNED,
            discovered_device=disc,
        ).exists()
        assert NetworkChangeEvent.objects.filter(
            event_type=NetworkChangeEvent.EventType.HOSTNAME_CHANGED,
            discovered_device=disc,
        ).exists()

        # Scan 4: Same MAC moves to a new IP -> IP_CHANGED
        scan4 = DiscoveryScan.objects.create(target_cidr="10.20.30.0/24", status="running")
        batch4 = [
            DiscoveredHostRecord(
                ip_address="10.20.30.15",
                mac_address="00:50:56:AA:BB:01",
                hostname="vm-web-01-prod.local",
                manufacturer="VMware, Inc.",
                device_type=Device.DeviceType.SERVER,
                confidence_score=85,
                discovery_methods=["arp", "icmp"],
                is_reachable=True,
                open_ports=[22, 443],
                subnet_cidr="10.20.30.0/24",
            )
        ]
        NetworkDiscoveryEngine.sync_discovered_inventory(batch4, "10.20.30.0/24", scan_obj=scan4)
        disc.refresh_from_db()
        assert disc.ip_address == "10.20.30.15"
        assert NetworkChangeEvent.objects.filter(
            event_type=NetworkChangeEvent.EventType.IP_CHANGED,
            discovered_device=disc,
        ).exists()

    def test_discovery_ui_trust_classification_and_deduplicated_registration(self, operator_client):
        client, _ = operator_client
        disc = DiscoveredDevice.objects.create(
            ip_address="10.50.0.25",
            mac_address="00:1A:2B:55:66:77",
            hostname="branch-sw-01",
            manufacturer="Cisco Systems",
            device_type=Device.DeviceType.SWITCH,
            confidence_score=85,
            is_reachable=True,
        )

        # 1. Render /discovery/ UI page
        page_res = client.get(reverse("devices:discovery"))
        assert page_res.status_code == 200
        assert b"Network Discovery" in page_res.content
        assert b"10.50.0.25" in page_res.content

        # 2. Classify device as Trusted & manual device_type override
        cls_res = client.post(
            f"/api/discovery/devices/{disc.id}/classify/",
            {"trust_status": "trusted", "device_type": "router"},
            format="json",
        )
        assert cls_res.status_code == 200
        disc.refresh_from_db()
        assert disc.trust_status == DiscoveredDevice.TrustStatus.TRUSTED
        assert disc.device_type == Device.DeviceType.ROUTER

        # 3. Register for monitoring (and verify deduplication on repeat call)
        reg_res1 = client.post(
            "/api/discovery/devices/register/",
            {"ids": [disc.id]},
            format="json",
        )
        assert reg_res1.status_code == 200
        assert reg_res1.data["registered_count"] == 1
        assert Device.objects.filter(ip_address="10.50.0.25").count() == 1

        # Calling register again updates existing monitored device instead of duplicating
        reg_res2 = client.post(
            "/api/discovery/devices/register/",
            {"ids": [disc.id]},
            format="json",
        )
        assert reg_res2.status_code == 200
        assert Device.objects.filter(ip_address="10.50.0.25").count() == 1
        assert AuditLog.objects.filter(action="api_register_discovered_devices").exists()


# ============================================================================
# PHASE 7, 8, 9 & 10: DASHBOARD, ADVANCED SNMP, TOPOLOGY & RESOURCE ALERTS
# ============================================================================
@pytest.mark.django_db
class TestVigilPhases7To10MonitoringTopologyAndAlerts:
    def test_cpu_and_memory_resource_alerts_and_auto_resolution(self):
        """Tests Phase 8 & 10 CPU/Memory threshold evaluation and auto-resolution."""
        AlertThreshold.objects.create(
            name="Global Resource Threshold",
            cpu_warning_pct=75.0,
            cpu_critical_pct=90.0,
            memory_warning_pct=80.0,
            memory_critical_pct=95.0,
            is_active=True,
        )
        dev = Device.objects.create(
            name="Core-Compute-01",
            ip_address="10.60.0.10",
            device_type=Device.DeviceType.SERVER,
            status=Device.Status.ONLINE,
        )

        # Trigger Critical CPU (94%) and Warning Memory (84%)
        res = AlertEngine.evaluate_device_resources(dev, cpu_pct=94.0, memory_pct=84.0)
        assert res["cpu_alert"] is not None
        assert res["memory_alert"] is not None
        cpu_alert = Alert.objects.get(device=dev, alert_type=Alert.AlertType.HIGH_CPU, is_resolved=False)
        mem_alert = Alert.objects.get(device=dev, alert_type=Alert.AlertType.HIGH_MEMORY, is_resolved=False)
        assert cpu_alert.severity == Alert.Severity.CRITICAL
        assert mem_alert.severity == Alert.Severity.WARNING

        # Recovery: CPU drops to 30% and Memory drops to 45% -> both auto-resolve
        AlertEngine.evaluate_device_resources(dev, cpu_pct=30.0, memory_pct=45.0)
        cpu_alert.refresh_from_db()
        mem_alert.refresh_from_db()
        assert cpu_alert.is_resolved is True
        assert mem_alert.is_resolved is True

    def test_confirmed_vs_inferred_topology_links(self):
        """
        Requirement Part 6: Do not assume two devices are directly connected merely
        because they share a subnet. Distinguish confirmed links from inferred relationships.
        """
        rtr = Device.objects.create(
            name="Core-RTR-Top",
            ip_address="10.70.1.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
        )
        sw = Device.objects.create(
            name="Dist-SW-Top",
            ip_address="10.70.1.2",
            device_type=Device.DeviceType.SWITCH,
            status=Device.Status.ONLINE,
        )
        srv = Device.objects.create(
            name="App-SRV-Top",
            ip_address="10.70.1.20",
            device_type=Device.DeviceType.SERVER,
            status=Device.Status.ONLINE,
        )
        # Explicit LLDP neighbor description on router interface -> Confirmed Link
        NetworkInterface.objects.create(
            device=rtr,
            interface_name="Gi0/1",
            interface_index=1,
            description="LLDP Neighbor: Dist-SW-Top (Gi0/24)",
        )

        TopologyEngine.auto_discover_subnet_links()
        confirmed_conn = NetworkConnection.objects.get(source_device=rtr, destination_device=sw)
        assert confirmed_conn.is_confirmed is True
        assert confirmed_conn.discovery_method == NetworkConnection.DiscoveryMethod.LLDP

        inferred_conn = NetworkConnection.objects.filter(
            destination_device=srv,
            discovery_method=NetworkConnection.DiscoveryMethod.SUBNET_INFERRED,
        ).first()
        assert inferred_conn is not None
        assert inferred_conn.is_confirmed is False

        graph = TopologyEngine.build_topology_graph()
        assert graph["summary"]["confirmed_links"] >= 1
        assert graph["summary"]["inferred_links"] >= 1

    def test_dashboard_stats_includes_vigil_discovery_and_resource_fields(self, operator_client):
        client, _ = operator_client
        Device.objects.create(
            name="Mon-Srv-1",
            ip_address="10.80.0.10",
            status=Device.Status.ONLINE,
            cpu_utilization=42.0,
            memory_utilization=61.0,
        )
        DiscoveredDevice.objects.create(
            ip_address="10.80.0.99",
            device_type=Device.DeviceType.UNKNOWN,
            trust_status=DiscoveredDevice.TrustStatus.UNKNOWN,
        )
        res = client.get(reverse("api-dashboard-stats"))
        assert res.status_code == 200
        data = res.json()
        assert data["devices"]["discovered_total"] >= 1
        assert data["devices"]["unknown_inventory"] >= 1
        assert data["performance"]["avg_cpu_pct"] == 42.0
        assert data["performance"]["avg_memory_pct"] == 61.0


# ============================================================================
# PHASE 11 & 12: NETWORK UTILITIES, UPTIME REPORT & SECURITY HARDENING
# ============================================================================
@pytest.mark.django_db
class TestVigilPhase11And12UtilitiesAndSecurity:
    def test_network_utilities_engine_and_endpoints(self, operator_client):
        client, _ = operator_client

        # 1. DNS Resolution Check for localhost
        dns_res = client.post("/api/monitoring/utilities/dns/", {"target": "localhost"}, format="json")
        assert dns_res.status_code == 200
        assert dns_res.data["is_resolved"] is True

        # 2. TCP Port Check blocks unauthorized public internet host
        port_blocked = client.post(
            "/api/monitoring/utilities/ports/",
            {"host": "8.8.8.8", "ports": [53, 443]},
            format="json",
        )
        assert port_blocked.status_code == 400
        assert "authorized" in port_blocked.data["error"].lower()

        # 3. Traceroute Output Parser
        sample_tracert = """
Tracing route to 10.0.114.1 over a maximum of 15 hops
  1    <1 ms     1 ms     1 ms  10.0.114.1
Trace complete.
        """
        hops = NetworkUtilitiesEngine.parse_traceroute_output(sample_tracert)
        assert len(hops) == 1
        assert hops[0].hop == 1
        assert hops[0].ip_address == "10.0.114.1"
        assert hops[0].rtt_ms == 1.0

        # 4. Uptime SLA Report View & API
        ui_res = client.get(reverse("monitoring:utilities"))
        assert ui_res.status_code == 200
        assert b"Network Utilities" in ui_res.content

        sla_res = client.get("/api/monitoring/utilities/uptime-report/?days=7")
        assert sla_res.status_code == 200
        assert "fleet_average_uptime" in sla_res.data

    def test_viewer_rbac_cannot_start_scan_or_register_devices(self, viewer_client):
        """Verifies RBAC protection on discovery scans and device onboarding."""
        client, _ = viewer_client
        scan_res = client.post(
            "/api/discovery/scans/start/",
            {"target_cidr": "192.168.1.0/29"},
            format="json",
        )
        assert scan_res.status_code == 403

        reg_res = client.post(
            "/api/discovery/devices/register/",
            {"ids": [1]},
            format="json",
        )
        assert reg_res.status_code == 403
