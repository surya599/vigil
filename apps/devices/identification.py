"""
VIGIL Multi-Evidence Device Fingerprinting & IEEE MAC OUI Identification Engine.

Combines:
1. Authoritative IEEE MAC Registry (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit) via `IEEEOUIRegistry`
2. Locally Administered Address (LAA) & MAC randomization bit analysis
3. Explicit separation of NIC/wireless chipset manufacturers (Intel, MediaTek, Lite-On,
   AltoBeam, Realtek, Broadcom, Qualcomm) from whole-device brands
4. Multi-method hostnames (Reverse DNS PTR, DHCP/Router DNS, NetBIOS, mDNS, LLMNR, SNMP)
5. SNMP `sysObjectID` and `sysDescr` fingerprints
6. Open TCP service port signatures (9100/631/515 Printer, 179 BGP Router, 3389 RDP, etc.)
7. Subnet default gateway topology role

Strict Anti-Fabrication Guarantees:
- Never invents a manufacturer from an IP address.
- Never claims an OUI vendor for a Locally Administered MAC.
- Never classifies a device as a Smartphone merely because its MAC vendor is a mobile
  chipset or mobile OEM without corroborating hostname/mDNS/DHCP/service evidence.
- Every inferred classification carries an explicit confidence level:
  High (>= 80), Medium (50-79), Low (1-49), or Unknown (0).
"""
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from devices.oui_registry import IEEEOUIRegistry, MACVendorLookupResult


# SNMP Enterprise sysObjectID Prefixes (1.3.6.1.4.1.<enterprise_id>)
SNMP_ENTERPRISE_MAP: Dict[str, Tuple[str, str]] = {
    "1.3.6.1.4.1.9": ("Cisco Systems", "router"),
    "1.3.6.1.4.1.30065": ("Arista Networks", "switch"),
    "1.3.6.1.4.1.2636": ("Juniper Networks", "router"),
    "1.3.6.1.4.1.25461": ("Palo Alto Networks", "firewall"),
    "1.3.6.1.4.1.12356": ("Fortinet", "firewall"),
    "1.3.6.1.4.1.14988": ("MikroTik", "router"),
    "1.3.6.1.4.1.41112": ("Ubiquiti Inc.", "access_point"),
    "1.3.6.1.4.1.14823": ("Aruba Networks (HPE)", "access_point"),
    "1.3.6.1.4.1.8072": ("Linux (Net-SNMP)", "server"),
    "1.3.6.1.4.1.311": ("Microsoft Corporation", "server"),
    "1.3.6.1.4.1.11": ("Hewlett-Packard", "printer"),
    "1.3.6.1.4.1.2435": ("Brother Industries", "printer"),
    "1.3.6.1.4.1.6574": ("Synology Inc.", "appliance"),
}


@dataclass
class DeviceClassificationResult:
    """Encapsulates the result of multi-evidence device fingerprinting."""
    device_type: str
    manufacturer: str  # Kept for backward compatibility; equals display MAC vendor or SNMP vendor
    confidence_score: int
    confidence_label: str  # 'High', 'Medium', 'Low', or 'Unknown'
    reason: str
    mac_address_type: str = "unknown"  # 'global', 'locally_administered', 'randomized_likely', 'unknown'
    mac_vendor: str = ""  # Registered IEEE OUI vendor, 'Locally Administered MAC', or 'Unknown Vendor'
    estimated_brand: str = ""  # Separate whole-device brand when supported by evidence
    is_chipset_oem: bool = False
    identification_status: str = "pending"  # 'identified', 'partial', 'pending', 'manual'
    evidence_items: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class DeviceIdentificationEngine:
    """
    Combines authoritative IEEE MAC OUI lookup, LAA/randomization analysis,
    SNMP sysDescr/sysObjectID, multi-method hostnames, open service ports,
    and gateway topology role to classify discovered devices with explicit confidence.
    """

    @staticmethod
    def inspect_mac(mac_address: Optional[str]) -> MACVendorLookupResult:
        """Performs full IEEE MA-L / MA-M / MA-S + LAA lookup via `IEEEOUIRegistry`."""
        return IEEEOUIRegistry.lookup(mac_address)

    @classmethod
    def lookup_mac_vendor(cls, mac_address: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        Backward-compatible helper returning `(vendor_or_status, optional_infra_type_hint)`.
        Never fabricates vendors or assumes 'mobile' for randomized/mobile-OUI MACs.
        """
        res = cls.inspect_mac(mac_address)
        if not res.is_valid:
            return "", None
        if res.mac_address_type in ("locally_administered", "randomized_likely"):
            return res.display_vendor, res.default_type_hint
        if res.registered_vendor == "Unknown Vendor":
            return "", None
        return res.registered_vendor, res.default_type_hint

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 80:
            return "High"
        if score >= 50:
            return "Medium"
        if score > 0:
            return "Low"
        return "Unknown"

    @staticmethod
    def _infer_from_hostname(hostname: str) -> Tuple[Optional[str], Optional[str], str]:
        """
        Extracts `(device_type, brand_hint, reason_note)` from a resolved hostname
        (PTR, NetBIOS, mDNS, LLMNR, DHCP, or SNMP sysName).
        """
        hn = hostname.lower().strip()
        if not hn:
            return None, None, ""

        # Brand extraction from hostname tokens
        brand_hint: Optional[str] = None
        brand_patterns = (
            (("macbook", "imac", "mac-mini", "macpro", "iphone", "ipad", "apple-tv", "airpods"), "Apple"),
            (("galaxy", "sm-s", "sm-g", "sm-a", "samsung", "-s-a1", "-s-a2", "-s-a3", "-s-a5", "-s-s2", "-s-m1", "-s-m3"), "Samsung"),
            (("pixel-", "chromecast", "nest-", "google-home"), "Google"),
            (("realme", "rmx"), "Realme"),
            (("oppo", "cph"), "OPPO"),
            (("vivo",), "vivo"),
            (("redmi", "xiaomi", "poco", "mi-"), "Xiaomi"),
            (("oneplus",), "OnePlus"),
            (("thinkpad", "ideapad", "legion", "lenovo"), "Lenovo"),
            (("latitude", "optiplex", "xps", "inspiron", "alienware", "poweredge"), "Dell"),
            (("elitebook", "probook", "pavilion", "laserjet", "officejet", "deskjet", "hp-"), "HP"),
            (("brother", "brw", "brn"), "Brother"),
            (("epson",), "Epson"),
            (("canon",), "Canon"),
            (("synology", "diskstation", "rackstation"), "Synology"),
            (("qnap",), "QNAP"),
            (("mikrotik", "routeros"), "MikroTik"),
            (("unifi", "ubnt", "edgerouter", "edgeswitch"), "Ubiquiti"),
            (("fortigate", "forti"), "Fortinet"),
            (("paloalto",), "Palo Alto Networks"),
            (("syrotech", "rtk_gw", "rtk-gw"), "Syrotech"),
        )
        for tokens, b_name in brand_patterns:
            if any(t in hn for t in tokens):
                brand_hint = b_name
                break

        # Category classification from hostname nomenclature
        if any(k in hn for k in ("fw", "firewall", "paloalto", "fortigate", "forti", "opnsense", "pfsense")):
            return "firewall", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("core-rtr", "router", "gw", "gateway", "rtr", "mikrotik", "edgerouter", "syrotech", "ont", "rtk_gw")):
            return "router", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("sw-", "switch", "dist-", "access-sw", "arista", "edgeswitch", "procurve", "catalyst")):
            return "switch", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("ap-", "wifi-ap", "wlan-ap", "unifi-ap", "aironet", "access-point")):
            return "access_point", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("prn", "print", "laserjet", "officejet", "deskjet", "brother", "brw", "canon", "epson", "np")):
            return "printer", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("ipad", "galaxy-tab", "sm-t", "sm-x", "tablet", "surface-go")):
            return "tablet", brand_hint, f"Hostname pattern ({hostname})"
        if any(
            k in hn
            for k in (
                "iphone",
                "android",
                "galaxy",
                "sm-s",
                "sm-g",
                "sm-a",
                "pixel",
                "oneplus",
                "realme",
                "rmx",
                "oppo",
                "vivo",
                "redmi",
                "poco",
                "-s-a1",
                "-s-a2",
                "-s-a3",
                "-s-a5",
                "-s-s2",
            )
        ):
            return "smartphone", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("macbook", "laptop", "thinkpad", "ideapad", "latitude", "elitebook", "probook", "xps", "-nb", "notebook")):
            return "laptop", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("desktop-", "workstation", "imac", "mac-mini", "optiplex", "inspiron", "-pc", "win11", "win10")):
            return "desktop", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("srv", "server", "prod-", "db-", "sql", "k8s", "node", "esxi", "pve", "proxmox", "ubuntu-srv")):
            return "server", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("nas", "synology", "diskstation", "qnap", "truenas", "netapp")):
            return "appliance", brand_hint, f"Hostname pattern ({hostname})"
        if any(k in hn for k in ("cam", "camera", "nvr", "dvr", "iot", "esp32", "esp8266", "tasmota", "shelly", "chromecast", "echo", "sonos", "hue", "smarttv", "bravia", "webos", "roku", "raspberrypi")):
            return "iot", brand_hint, f"Hostname pattern ({hostname})"

        return None, brand_hint, f"Hostname resolved ({hostname})"

    @classmethod
    def identify_device(
        cls,
        ip_address: str,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        hostname_source: str = "",
        all_hostnames: Optional[Dict[str, str]] = None,
        sys_description: Optional[str] = None,
        sys_object_id: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        is_gateway: bool = False,
        is_local_host: bool = False,
    ) -> DeviceClassificationResult:
        """
        Evaluates all available telemetry signals to determine:
        - `mac_vendor` (Registered IEEE OUI/MA-M/MA-S vendor or LAA status)
        - `mac_address_type` (`global`, `locally_administered`, `randomized_likely`, `unknown`)
        - `estimated_brand` (Device brand separated from NIC/chipset vendor)
        - `device_type`
        - `confidence_score` (0-100) and `confidence_label` (`High`, `Medium`, `Low`, `Unknown`)
        - `identification_status` (`identified`, `partial`, `pending`)
        """
        mac_info = cls.inspect_mac(mac_address)
        mac_address_type = mac_info.mac_address_type
        mac_vendor = mac_info.display_vendor if mac_info.is_valid else ""
        estimated_brand = mac_info.estimated_brand
        is_chipset_oem = mac_info.is_chipset_oem

        device_type = "unknown"
        score = 0
        reasons: List[str] = []
        ports = set(open_ports or [])

        # 1. Evaluate MAC Address & IEEE OUI Registry Evidence
        if mac_info.is_valid:
            if mac_info.mac_address_type == "global":
                if mac_info.registered_vendor != "Unknown Vendor":
                    score += 30
                    if mac_info.is_chipset_oem:
                        reasons.append(f"IEEE {mac_info.registry_block} NIC/Chipset OUI ({mac_info.registered_vendor})")
                    else:
                        reasons.append(f"IEEE {mac_info.registry_block} Vendor ({mac_info.registered_vendor})")
                    if mac_info.default_type_hint:
                        device_type = mac_info.default_type_hint
                        score += 20
                else:
                    reasons.append(f"Unregistered Global OUI ({mac_info.matched_prefix})")
            elif mac_info.mac_address_type == "randomized_likely":
                reasons.append("Locally Administered Bit Set — Randomized / Private MAC (likely)")
            elif mac_info.mac_address_type == "locally_administered":
                reasons.append(f"Locally Administered MAC ({mac_info.display_vendor})")
                if mac_info.default_type_hint:
                    device_type = mac_info.default_type_hint
                    score += 25

        # 2. SNMP sysObjectID Fingerprint (Authoritative infrastructure signal)
        if sys_object_id:
            oid_str = sys_object_id.strip().lstrip(".")
            for prefix, (snmp_vendor, snmp_type) in SNMP_ENTERPRISE_MAP.items():
                if oid_str.startswith(prefix):
                    if not estimated_brand:
                        estimated_brand = snmp_vendor
                    if not mac_vendor or mac_address_type != "global" or mac_info.registered_vendor == "Unknown Vendor":
                        mac_vendor = snmp_vendor
                    device_type = snmp_type
                    score += 45
                    reasons.append(f"SNMP sysObjectID ({snmp_vendor})")
                    break

        # 3. SNMP sysDescr Analysis (Authoritative OS/platform signal)
        if sys_description:
            desc_lower = sys_description.lower()
            score += 40
            if any(k in desc_lower for k in ("palo alto", "fortigate", "fortios", "asa ", "firepower", "opnsense", "pfsense")):
                device_type = "firewall"
                reasons.append("SNMP sysDescr (Firewall OS)")
            elif any(k in desc_lower for k in ("arista", "catalyst", "procurve", "edgeswitch", "nx-os", "eos ")):
                device_type = "switch"
                reasons.append("SNMP sysDescr (Switch OS)")
            elif any(k in desc_lower for k in ("ios xe", "ios-xr", "cisco ios", "routeros", "junos", "vyos", "edgerouter", "gpon", "ont")):
                device_type = "router"
                reasons.append("SNMP sysDescr (Router OS)")
            elif any(k in desc_lower for k in ("unifi ap", "aironet", "arubaos", "openwrt", "access point")):
                device_type = "access_point"
                reasons.append("SNMP sysDescr (Wireless AP)")
            elif any(k in desc_lower for k in ("jetdirect", "laserjet", "officejet", "brother", "canon", "epson")):
                device_type = "printer"
                reasons.append("SNMP sysDescr (Network Printer)")
            elif any(k in desc_lower for k in ("synology", "qnap", "truenas", "netapp")):
                device_type = "appliance"
                reasons.append("SNMP sysDescr (Storage Appliance)")
            elif any(k in desc_lower for k in ("linux", "ubuntu", "debian", "red hat", "windows server", "esxi", "darwin")):
                if device_type == "unknown":
                    device_type = "server"
                reasons.append("SNMP sysDescr (Server/Host OS)")

        # 4. Multi-Method Hostname Evidence (PTR, DHCP, NetBIOS, mDNS, LLMNR, SNMP)
        candidate_names: List[Tuple[str, str]] = []
        if hostname:
            candidate_names.append((hostname_source or "dns", hostname))
        if all_hostnames:
            for src, hn_val in all_hostnames.items():
                if hn_val and (src, hn_val) not in candidate_names:
                    candidate_names.append((src, hn_val))

        if candidate_names:
            score += 25
            for src, hn_val in candidate_names:
                inferred_type, inferred_brand, hn_reason = cls._infer_from_hostname(hn_val)
                if inferred_brand and not estimated_brand:
                    estimated_brand = inferred_brand
                if inferred_type and device_type == "unknown":
                    device_type = inferred_type
                    score += 25
                    reasons.append(f"{hn_reason} via {src.upper()}")
                    break
            else:
                # Hostname resolved (e.g. 'vsbreddy' via NetBIOS/PTR), even if it's a custom personal name
                primary_src, primary_hn = candidate_names[0]
                reasons.append(f"Hostname '{primary_hn}' ({primary_src.upper()})")
                # If NetBIOS resolved a workstation name and NIC is an Intel/Liteon/Realtek PC adapter
                if (primary_src == "netbios" or "netbios" in (all_hostnames or {})) and device_type == "unknown":
                    device_type = "laptop" if is_local_host else "desktop"
                    score += 20
                    reasons.append("NetBIOS Workstation Service")

        # 5. Open TCP Port Signatures
        if ports:
            score += 15
            if ports.intersection({9100, 515, 631}) and device_type in ("unknown", "server"):
                device_type = "printer"
                score += 30
                reasons.append(f"Print service port ({sorted(ports.intersection({9100, 515, 631}))[0]})")
            elif 179 in ports and device_type == "unknown":
                device_type = "router"
                score += 25
                reasons.append("BGP port 179")
            elif 3389 in ports and device_type == "unknown":
                device_type = "desktop"
                score += 20
                reasons.append("RDP port 3389")
            elif ports.intersection({5432, 3306, 27017, 6379, 22}) and device_type == "unknown":
                if not is_gateway:
                    device_type = "server"
                    score += 20
                    reasons.append(f"Server ports ({','.join(str(p) for p in sorted(ports)[:3])})")
            elif ports.intersection({80, 443}) and is_gateway:
                score += 15
                reasons.append("Gateway Web Admin UI (80/443)")

        # 6. Default Gateway Role Heuristic
        if is_gateway:
            score += 40
            if device_type in ("unknown", "server"):
                device_type = "router"
            reasons.append("Default subnet gateway")

        # 7. Local VIGIL Host Heuristic
        if is_local_host:
            score += 40
            if device_type in ("unknown", "desktop"):
                device_type = "laptop"
            reasons.append("Local VIGIL host interface")

        # 8. Compute Final Confidence Score & Identification Status
        # Remember: Never classify a device as a smartphone solely from a mobile chipset/OUI or LAA MAC!
        if device_type == "unknown":
            if mac_info.mac_address_type == "global" and mac_info.registered_vendor != "Unknown Vendor":
                final_score = min(max(score, 25), 45)  # Low confidence: MAC vendor known, device type unknown
                id_status = "partial"
            elif candidate_names:
                final_score = min(max(score, 30), 45)
                id_status = "partial"
            else:
                final_score = 0
                id_status = "pending"
        else:
            final_score = min(max(score, 50), 99)
            id_status = "identified"

        confidence_label = cls._confidence_label(final_score)
        reason_str = " + ".join(reasons) if reasons else "Identification pending — no hostname, SNMP, or IEEE OUI match yet"

        return DeviceClassificationResult(
            device_type=device_type,
            manufacturer=mac_vendor,
            confidence_score=final_score,
            confidence_label=confidence_label,
            reason=reason_str,
            mac_address_type=mac_address_type,
            mac_vendor=mac_vendor,
            estimated_brand=estimated_brand,
            is_chipset_oem=is_chipset_oem,
            identification_status=id_status,
            evidence_items=reasons,
        )
