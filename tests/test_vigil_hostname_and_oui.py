"""
VIGIL Automated Test Suite: Multi-Method Hostname Discovery, IEEE MA-L/MA-M/MA-S
MAC Vendor Registry, Locally Administered & Randomized MAC Detection, and
Multi-Evidence Device Fingerprinting.
"""
import socket
import struct
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from devices.discovery import DiscoveredHostRecord, NetworkDiscoveryEngine
from devices.hostname_resolver import HostnameResolver
from devices.identification import DeviceIdentificationEngine
from devices.models import Device, DiscoveredDevice, NetworkChangeEvent
from devices.oui_registry import IEEEOUIRegistry


# ─── 1. IEEE OUI Registry & MAC Address Analysis Tests ────────────────────────

def test_valid_global_mac_addresses_and_ieee_lookup():
    """
    Tests normalization and authoritative IEEE MA-L (/24), MA-M (/28), and MA-S (/36)
    vendor lookups on real globally administered MAC addresses.
    """
    # 24-bit MA-L lookups (including the user's real Wi-Fi MAC prefixes)
    syrotech = IEEEOUIRegistry.lookup("54-47-e8-bf-4f-6d")
    assert syrotech.is_valid is True
    assert syrotech.normalized_mac == "54:47:E8:BF:4F:6D"
    assert syrotech.mac_address_type == "global"
    assert "Syrotech" in syrotech.registered_vendor
    assert syrotech.registry_block == "MA-L (24-bit)"
    assert syrotech.estimated_brand == "Syrotech"

    intel = IEEEOUIRegistry.lookup("48:68:4A:63:11:4F")
    assert intel.is_valid is True
    assert intel.mac_address_type == "global"
    assert "Intel" in intel.registered_vendor
    assert intel.is_chipset_oem is True
    # NIC chipset OEM must not claim the whole device brand
    assert intel.estimated_brand == ""

    altobeam = IEEEOUIRegistry.lookup("4C:60:BA:67:DC:86")
    assert altobeam.is_valid is True
    assert altobeam.mac_address_type == "global"
    assert "AltoBeam" in altobeam.registered_vendor
    assert altobeam.is_chipset_oem is True

    realme = IEEEOUIRegistry.lookup("44:46:87:34:8A:27")
    assert realme.is_valid is True
    assert realme.mac_address_type == "global"
    assert "Realme" in realme.registered_vendor
    assert realme.estimated_brand == "Realme"
    # Consumer/mobile brand must not default to 'smartphone' from MAC alone
    assert realme.default_type_hint is None


def test_ieee_ma_m_28bit_and_ma_s_36bit_prefix_lookups():
    """
    Verifies longest-prefix matching across 36-bit (MA-S) and 28-bit (MA-M) IEEE blocks.
    """
    IEEEOUIRegistry.ensure_loaded()
    # Pick a 36-bit MA-S entry (`00:1B:C5:00:10/36` -> OpenRB.com, Direct SIA)
    ma_s_res = IEEEOUIRegistry.lookup("00:1B:C5:00:15:AA")
    assert ma_s_res.is_valid is True
    assert ma_s_res.mac_address_type == "global"
    assert ma_s_res.registry_block == "MA-S (36-bit)"
    assert ma_s_res.registered_vendor != "Unknown Vendor"

    # Pick any loaded 28-bit MA-M key and verify 28-bit lookup resolution
    assert len(IEEEOUIRegistry._ma_m_28) > 1000
    sample_28_prefix = next(iter(IEEEOUIRegistry._ma_m_28.keys()))
    sample_mac = ":".join(
        [
            sample_28_prefix[0:2],
            sample_28_prefix[2:4],
            sample_28_prefix[4:6],
            f"{sample_28_prefix[6]}A",
            "11",
            "22",
        ]
    )
    ma_m_res = IEEEOUIRegistry.lookup(sample_mac)
    assert ma_m_res.is_valid is True
    assert ma_m_res.registry_block == "MA-M (28-bit)"
    assert ma_m_res.registered_vendor != "Unknown Vendor"


def test_locally_administered_and_randomized_mac_detection():
    """
    Verifies locally administered bit (0x02 of first octet) detection:
    - High-entropy random client MACs are labeled 'Randomized / Private MAC (likely)'
      with registered_vendor='Locally Administered MAC'.
    - Known hypervisor/admin-assigned LAA MACs are labeled 'Locally Administered MAC'
      without assuming randomization.
    """
    # Randomized / Private MACs from real Wi-Fi scan
    for r_mac in ("C2:33:ED:0A:A8:85", "0A:F6:9C:00:AB:37", "AA:A8:BE:5D:5F:46"):
        res = IEEEOUIRegistry.lookup(r_mac)
        assert res.is_valid is True
        assert res.mac_address_type == "randomized_likely"
        assert res.registered_vendor == "Locally Administered MAC"
        assert "Randomized / Private MAC (likely)" in res.display_vendor
        assert res.default_type_hint is None

    # Low-entropy manually assigned Locally Administered MAC (not randomized)
    admin_mac = IEEEOUIRegistry.lookup("02:00:00:00:00:01")
    assert admin_mac.is_valid is True
    assert admin_mac.mac_address_type == "locally_administered"
    assert admin_mac.registered_vendor == "Locally Administered MAC"
    assert admin_mac.display_vendor == "Locally Administered MAC"

    # QEMU/KVM Virtual NIC (Locally Administered 52:54:00)
    kvm_mac = IEEEOUIRegistry.lookup("52:54:00:12:34:56")
    assert kvm_mac.is_valid is True
    assert kvm_mac.mac_address_type == "locally_administered"
    assert kvm_mac.registered_vendor == "Locally Administered MAC"
    assert "QEMU / KVM" in kvm_mac.display_vendor


def test_unknown_mac_vendor_and_invalid_macs():
    """
    Ensures unassigned global OUIs return 'Unknown Vendor' and malformed MACs are rejected safely.
    """
    # Unassigned global prefix (bit 1 of first octet is 0: 0xFC & 0x02 == 0)
    unassigned = IEEEOUIRegistry.lookup("FC:FF:FF:11:22:33")
    assert unassigned.is_valid is True
    assert unassigned.mac_address_type == "global"
    assert unassigned.registered_vendor == "Unknown Vendor"
    assert unassigned.display_vendor == "Unknown Vendor"

    # Invalid MACs
    for bad in ("", None, "not-a-mac", "192.168.1.1", "00:11:22"):
        bad_res = IEEEOUIRegistry.lookup(bad)
        assert bad_res.is_valid is False
        assert bad_res.normalized_mac == ""


# ─── 2. Multi-Method Hostname Discovery Tests ─────────────────────────────────

def test_hostname_validation_never_accepts_ip_addresses():
    """Never allows an IP address or dashed-IP placeholder to be used as a hostname."""
    assert HostnameResolver.is_valid_hostname("192.168.1.34", ip_address="192.168.1.34") is False
    assert HostnameResolver.is_valid_hostname("10.0.0.1") is False
    assert HostnameResolver.is_valid_hostname("fe80::1") is False
    assert HostnameResolver.is_valid_hostname("192-168-1-34", ip_address="192.168.1.34") is False
    assert HostnameResolver.is_valid_hostname("localhost") is False
    assert HostnameResolver.is_valid_hostname("vsbreddy", ip_address="192.168.1.34") is True
    assert HostnameResolver.is_valid_hostname("office-printer.local", ip_address="192.168.1.50") is True


def test_reverse_dns_success_and_failure():
    """Tests Reverse DNS PTR resolution success, IP rejection, and timeout failure."""
    # Build a synthetic DNS PTR response packet for 34.1.168.192.in-addr.arpa -> 'workstation-01.lan'
    tid, query_pkt = HostnameResolver._build_ptr_query_packet("192.168.1.34", tx_id=0x1234)
    q_section = query_pkt[12:]
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    ans_name = b"\xc0\x0c"  # pointer to question name
    rdata = b"\x0eworkstation-01\x03lan\x00"
    ans_rr = ans_name + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    resp_pkt = header + q_section + ans_rr

    parsed = HostnameResolver._parse_ptr_response_packet(resp_pkt, expected_tx_id=0x1234)
    assert parsed == "workstation-01.lan"

    # Failure / timeout handling
    with patch("socket.socket.recvfrom", side_effect=socket.timeout("timed out")):
        assert HostnameResolver.resolve_reverse_dns("192.168.1.99", dns_servers=["192.168.1.1"]) == ""


def test_netbios_discovery_success_and_timeout():
    """Tests RFC 1002 NetBIOS NBSTAT response parsing and timeout resilience."""
    # Construct a valid NBSTAT response containing 'VSBREDDY       ' (<00> workstation)
    header = b"\x12\x34\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    encoded_qname = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    rr_hdr = b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x1d"  # type 0x0021, class 1, ttl 0, rdlen 29
    num_names = b"\x01"
    # 15-byte padded ASCII name + suffix (0x00) + flags (0x0400 unique active)
    name_entry = b"VSBREDDY       " + b"\x00" + b"\x04\x00"
    mac_trailer = b"\x48\x68\x4a\x63\x11\x4f"
    nb_packet = header + encoded_qname + rr_hdr + num_names + name_entry + mac_trailer

    with patch("socket.socket.recvfrom", return_value=(nb_packet, ("192.168.1.34", 137))):
        with patch("socket.socket.sendto", return_value=len(nb_packet)):
            resolved = HostnameResolver.resolve_netbios("192.168.1.34", timeout=0.2)
            assert resolved == "VSBREDDY"

    # Timeout case
    with patch("socket.socket.recvfrom", side_effect=socket.timeout("nbns timeout")):
        assert HostnameResolver.resolve_netbios("192.168.1.34", timeout=0.1) == ""


def test_mdns_discovery_success_and_failure():
    """Tests mDNS (.local) reverse PTR response parsing and failure handling."""
    _, query_pkt = HostnameResolver._build_ptr_query_packet("192.168.1.40", tx_id=0, unicast_response=True)
    q_section = query_pkt[12:]
    header = struct.pack("!HHHHHH", 0x0000, 0x8400, 1, 1, 0, 0)
    rdata = b"\x0bmacbook-pro\x05local\x00"
    ans_rr = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    mdns_resp = header + q_section + ans_rr

    with patch("socket.socket.recvfrom", return_value=(mdns_resp, ("192.168.1.40", 5353))):
        with patch("socket.socket.sendto", return_value=len(query_pkt)):
            hn = HostnameResolver.resolve_mdns("192.168.1.40", timeout=0.2)
            assert hn == "macbook-pro.local"

    with patch("socket.socket.recvfrom", side_effect=socket.timeout("mdns timeout")):
        assert HostnameResolver.resolve_mdns("192.168.1.40", timeout=0.1) == ""


def test_multiple_hostname_sources_priority_and_collection():
    """
    Verifies that when multiple sources (e.g. PTR, NetBIOS, mDNS) return different names,
    all names are recorded in `all_hostnames` and the highest-priority source is chosen.
    """
    with patch.object(HostnameResolver, "resolve_reverse_dns", return_value="desktop-pc.home.arpa"), \
         patch.object(HostnameResolver, "resolve_dhcp_router_dns", return_value=""), \
         patch.object(HostnameResolver, "resolve_netbios", return_value="DESKTOP-PC"), \
         patch.object(HostnameResolver, "resolve_mdns", return_value="desktop-pc.local"):
        res = HostnameResolver.resolve_all("192.168.1.55", gateway_ip="192.168.1.1")
        assert res.hostname == "desktop-pc.home.arpa"
        assert res.source == "ptr"
        assert res.all_hostnames == {
            "ptr": "desktop-pc.home.arpa",
            "netbios": "DESKTOP-PC",
            "mdns": "desktop-pc.local",
        }


# ─── 3. Multi-Evidence Device Fingerprinting & Confidence Tests ───────────────

def test_device_classification_and_anti_hallucination_rules():
    """
    Verifies that:
    1. Mobile chipset / OEM MAC alone (e.g. Realme or AltoBeam or Randomized MAC) is NOT
       classified as a Smartphone without supporting hostname/service evidence.
    2. When a mobile hostname (e.g. 'Realme-RMX3840' or 'iPhone-15.local') IS present,
       it is classified as 'smartphone' with Medium/High confidence.
    3. Gateway router with Syrotech OUI is classified as 'router' with High confidence.
    """
    # Case A: Realme MAC OUI alone -> device_type must stay 'unknown', confidence 'Low'
    realme_only = DeviceIdentificationEngine.identify_device(
        ip_address="192.168.1.39",
        mac_address="44:46:87:34:8A:27",
        hostname="",
    )
    assert "Realme" in realme_only.mac_vendor
    assert realme_only.estimated_brand == "Realme"
    assert realme_only.device_type == "unknown"
    assert realme_only.confidence_label == "Low"

    # Case B: Realme MAC OUI + DHCP/mDNS hostname 'Realme-GT-Neo' -> 'smartphone', Medium/High confidence
    realme_with_hn = DeviceIdentificationEngine.identify_device(
        ip_address="192.168.1.39",
        mac_address="44:46:87:34:8A:27",
        hostname="Realme-GT-Neo",
        hostname_source="dhcp",
    )
    assert realme_with_hn.device_type == "smartphone"
    assert realme_with_hn.confidence_label in ("Medium", "High")

    # Case C: Randomized MAC alone -> 'unknown' device_type, 'Unknown' confidence
    rand_only = DeviceIdentificationEngine.identify_device(
        ip_address="192.168.1.43",
        mac_address="C2:33:ED:0A:A8:85",
    )
    assert rand_only.mac_address_type == "randomized_likely"
    assert rand_only.device_type == "unknown"
    assert rand_only.confidence_label == "Unknown"

    # Case D: Default Gateway with Syrotech OUI -> 'router', 'High' confidence
    gw_router = DeviceIdentificationEngine.identify_device(
        ip_address="192.168.1.1",
        mac_address="54:47:E8:BF:4F:6D",
        open_ports=[80, 443],
        is_gateway=True,
    )
    assert gw_router.device_type == "router"
    assert "Syrotech" in gw_router.mac_vendor
    assert gw_router.confidence_label == "High"


# ─── 4. Database Persistence, Hostname Preservation & Manual Overrides ────────

@pytest.mark.django_db
def test_previously_known_hostname_preservation_and_duplicate_prevention():
    """
    Verifies that:
    - When a device was previously discovered with a valid hostname ('vsbreddy')
      and a subsequent scan fails to resolve its hostname (''), the previously
      known hostname is preserved.
    - Re-scanning the same IP/MAC updates the existing record rather than creating duplicates.
    """
    rec1 = DiscoveredHostRecord(
        ip_address="192.168.1.34",
        mac_address="48:68:4A:63:11:4F",
        hostname="vsbreddy",
        hostname_source="netbios",
        discovered_hostnames={"netbios": "vsbreddy"},
        mac_address_type="global",
        mac_vendor="Intel Corporate",
        manufacturer="Intel Corporate",
        is_chipset_oem=True,
        device_type="laptop",
        confidence_score=85,
        confidence_label="High",
        classification_reason="IEEE MA-L NIC/Chipset OUI (Intel Corporate) + Hostname 'vsbreddy'",
        identification_status="identified",
        discovery_methods=["arp", "icmp", "netbios"],
        subnet_cidr="192.168.1.0/24",
    )
    NetworkDiscoveryEngine.sync_discovered_inventory([rec1], subnet_cidr="192.168.1.0/24")
    assert DiscoveredDevice.objects.filter(ip_address="192.168.1.34").count() == 1
    dev = DiscoveredDevice.objects.get(ip_address="192.168.1.34")
    assert dev.hostname == "vsbreddy"
    assert dev.hostname_source == "netbios"
    assert dev.last_hostname_resolved_at is not None

    # Second scan where NetBIOS/DNS temporarily fails (hostname="")
    rec2 = DiscoveredHostRecord(
        ip_address="192.168.1.34",
        mac_address="48:68:4A:63:11:4F",
        hostname="",
        hostname_source="none",
        discovered_hostnames={},
        mac_address_type="global",
        mac_vendor="Intel Corporate",
        manufacturer="Intel Corporate",
        is_chipset_oem=True,
        device_type="unknown",
        confidence_score=30,
        confidence_label="Low",
        classification_reason="IEEE MA-L NIC/Chipset OUI (Intel Corporate)",
        identification_status="partial",
        discovery_methods=["arp", "icmp"],
        subnet_cidr="192.168.1.0/24",
    )
    NetworkDiscoveryEngine.sync_discovered_inventory([rec2], subnet_cidr="192.168.1.0/24")
    assert DiscoveredDevice.objects.filter(ip_address="192.168.1.34").count() == 1
    dev.refresh_from_db()
    # Must preserve 'vsbreddy' and 'laptop'!
    assert dev.hostname == "vsbreddy"
    assert dev.hostname_source == "netbios"
    assert dev.device_type == "laptop"


@pytest.mark.django_db
def test_manual_hostname_and_device_type_overrides_preserved(client):
    """
    Verifies that operators can manually override both hostname and device_type via
    the Discovery UI / API, that IP addresses are rejected as manual hostnames,
    and that subsequent automatic scans do not overwrite manual overrides.
    """
    admin = User.objects.create_superuser("noc_admin", "admin@vigil.io", "pass1234")
    client.force_login(admin)

    dev = DiscoveredDevice.objects.create(
        ip_address="192.168.1.38",
        mac_address="4C:60:BA:67:DC:86",
        mac_address_type="global",
        mac_vendor="AltoBeam Inc.",
        manufacturer="AltoBeam Inc.",
        device_type="unknown",
        confidence_score=30,
    )

    # 1. Attempt to set an IP address as manual hostname -> must be rejected (400)
    bad_resp = client.post(
        f"/api/discovery/devices/{dev.id}/classify/",
        data={"hostname": "192.168.1.38"},
        content_type="application/json",
    )
    assert bad_resp.status_code == 400

    # 2. Valid manual hostname + device_type override via API
    ok_resp = client.post(
        f"/api/discovery/devices/{dev.id}/classify/",
        data={"hostname": "LivingRoom-SmartTV", "device_type": "iot", "trust_status": "trusted"},
        content_type="application/json",
    )
    assert ok_resp.status_code == 200
    dev.refresh_from_db()
    assert dev.hostname == "LivingRoom-SmartTV"
    assert dev.hostname_manually_set is True
    assert dev.hostname_source == "manual"
    assert dev.device_type == "iot"
    assert dev.type_manually_set is True
    assert dev.identification_status == "manual"
    assert dev.discovered_hostnames.get("manual") == "LivingRoom-SmartTV"

    # 3. Subsequent automated scan discovering a different PTR name must NOT overwrite manual name/type
    scan_rec = DiscoveredHostRecord(
        ip_address="192.168.1.38",
        mac_address="4C:60:BA:67:DC:86",
        hostname="auto-dhcp-host",
        hostname_source="dhcp",
        discovered_hostnames={"dhcp": "auto-dhcp-host"},
        mac_address_type="global",
        mac_vendor="AltoBeam Inc.",
        manufacturer="AltoBeam Inc.",
        device_type="desktop",
        confidence_score=60,
    )
    NetworkDiscoveryEngine.sync_discovered_inventory([scan_rec], subnet_cidr="192.168.1.0/24")
    dev.refresh_from_db()
    assert dev.hostname == "LivingRoom-SmartTV"
    assert dev.hostname_manually_set is True
    assert dev.device_type == "iot"
    # But the newly seen DHCP name is still recorded in discovered_hostnames for visibility!
    assert dev.discovered_hostnames.get("dhcp") == "auto-dhcp-host"
    assert dev.discovered_hostnames.get("manual") == "LivingRoom-SmartTV"
