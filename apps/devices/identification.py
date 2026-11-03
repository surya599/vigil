"""
VIGIL Phase 4: Device Identification, Confidence Scoring & IEEE MAC OUI Vendor Lookup.

Identifies network device manufacturers and classifications (Router, Switch,
Access Point, Firewall, Server, Printer, Laptop, Desktop, Mobile Phone,
Network Appliance, or Unknown) using:
1. IEEE MAC OUI prefix database
2. SNMP sysObjectID & sysDescr fingerprints
3. Reverse DNS & hostname nomenclature
4. Open TCP service port signatures (e.g., 9100/631 Printer, 179 BGP Router)
5. Subnet default gateway role

Never fabricates device attributes when identification signals are absent.
"""
import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple


# Curated IEEE MAC OUI Prefix Table (Normalized 'XX:XX:XX' -> (Manufacturer, Default Type Hint))
OUI_VENDOR_DATABASE: Dict[str, Tuple[str, Optional[str]]] = {
    # Cisco Systems
    "00:00:0C": ("Cisco Systems", "router"),
    "00:1A:2B": ("Cisco Systems", "router"),
    "00:1B:54": ("Cisco Systems", "switch"),
    "00:25:9C": ("Cisco-Linksys", "router"),
    "F8:72:EA": ("Cisco Meraki", "access_point"),
    "00:18:0A": ("Cisco Meraki", "access_point"),
    # Arista / Juniper / Extreme
    "00:1C:73": ("Arista Networks", "switch"),
    "28:99:3A": ("Arista Networks", "switch"),
    "00:05:85": ("Juniper Networks", "router"),
    "2C:6B:F5": ("Juniper Networks", "switch"),
    # Palo Alto / Fortinet / SonicWall (Firewalls)
    "00:1B:17": ("Palo Alto Networks", "firewall"),
    "7C:89:C1": ("Palo Alto Networks", "firewall"),
    "00:09:0F": ("Fortinet", "firewall"),
    "90:6C:AC": ("Fortinet", "firewall"),
    "00:17:C5": ("SonicWall", "firewall"),
    # Ubiquiti / MikroTik / Aruba / Ruckus / TP-Link / Netgear / D-Link
    "24:A4:3C": ("Ubiquiti Inc.", "access_point"),
    "F0:9F:C2": ("Ubiquiti Inc.", "access_point"),
    "74:83:C2": ("Ubiquiti Inc.", "access_point"),
    "B8:69:F4": ("MikroTik", "router"),
    "4C:5E:0C": ("MikroTik", "router"),
    "D4:CA:6D": ("MikroTik", "router"),
    "00:0B:86": ("Aruba Networks (HPE)", "access_point"),
    "94:B4:0F": ("Aruba Networks (HPE)", "access_point"),
    "50:C7:BF": ("TP-Link Systems", "router"),
    "E8:DE:27": ("TP-Link Systems", "access_point"),
    "A0:04:60": ("NETGEAR", "switch"),
    "20:4E:7F": ("NETGEAR", "router"),
    # Virtualization & Cloud Hypervisors (Servers)
    "00:50:56": ("VMware, Inc.", "server"),
    "00:0C:29": ("VMware, Inc.", "server"),
    "00:05:69": ("VMware, Inc.", "server"),
    "00:15:5D": ("Microsoft Hyper-V", "server"),
    "52:54:00": ("QEMU / KVM Virtual NIC", "server"),
    "08:00:27": ("Oracle VirtualBox", "server"),
    # Enterprise Servers & Workstations (Dell, HPE, Supermicro, Lenovo, Intel)
    "00:14:22": ("Dell Inc.", None),
    "F8:B1:56": ("Dell Inc.", None),
    "18:66:DA": ("Dell Inc.", "server"),
    "3C:D9:2B": ("Hewlett Packard Enterprise", "server"),
    "94:57:A5": ("Hewlett Packard Enterprise", None),
    "00:25:90": ("Super Micro Computer", "server"),
    "AC:1F:6B": ("Super Micro Computer", "server"),
    "00:21:CC": ("Lenovo", "laptop"),
    "60:57:18": ("Intel Corporate", None),
    "A4:BB:6D": ("Intel Corporate", None),
    # Printers (HP, Brother, Canon, Epson, Xerox, Zebra)
    "00:01:E6": ("Hewlett-Packard (Print)", "printer"),
    "00:80:77": ("Brother Industries", "printer"),
    "30:05:5C": ("Brother Industries", "printer"),
    "00:1E:8F": ("Canon Inc.", "printer"),
    "00:26:AB": ("Seiko Epson Corp.", "printer"),
    "00:00:AA": ("Xerox Corporation", "printer"),
    # Apple / Samsung / Google / Xiaomi / OnePlus (Mobile & Laptops)
    "F0:18:98": ("Apple, Inc.", None),
    "A8:20:66": ("Apple, Inc.", None),
    "3C:22:FB": ("Apple, Inc.", "laptop"),
    "28:CF:E9": ("Apple, Inc.", "mobile"),
    "FC:FC:48": ("Apple, Inc.", None),
    "00:16:32": ("Samsung Electronics", "mobile"),
    "5C:3C:27": ("Samsung Electronics", "mobile"),
    "64:BC:0C": ("LG Electronics", "mobile"),
    "28:6C:07": ("Xiaomi Communications", "mobile"),
    "94:65:2D": ("OnePlus Technology", "mobile"),
    "3C:5A:B4": ("Google, Inc.", "mobile"),
    # IoT & Network Appliances (Synology, QNAP, Raspberry Pi)
    "00:11:32": ("Synology Inc.", "appliance"),
    "24:5E:BE": ("QNAP Systems", "appliance"),
    "B8:27:EB": ("Raspberry Pi Foundation", "appliance"),
    "DC:A6:32": ("Raspberry Pi Trading", "appliance"),
    "E4:5F:01": ("Raspberry Pi Trading", "appliance"),
}


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
    """Encapsulates the result of multi-signal device identification."""
    device_type: str
    manufacturer: str
    confidence_score: int
    confidence_label: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


class DeviceIdentificationEngine:
    """
    Combines MAC OUI vendor lookup, SNMP sysDescr/sysObjectID, hostname patterns,
    open service ports, and gateway topology role to classify discovered devices
    with an explicit confidence score (0-100%).
    """

    @staticmethod
    def lookup_mac_vendor(mac_address: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        Looks up manufacturer name and optional default device_type hint from a MAC address.
        Returns ("", None) when the MAC is missing or unrecognized (never invents vendors).
        """
        if not mac_address:
            return "", None
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
        if len(cleaned) < 6:
            return "", None
        oui = f"{cleaned[0:2]}:{cleaned[2:4]}:{cleaned[4:6]}"
        if oui in OUI_VENDOR_DATABASE:
            return OUI_VENDOR_DATABASE[oui]

        # Check locally administered / randomized MAC bit (bit 1 of first octet)
        first_octet = int(cleaned[0:2], 16)
        if first_octet & 0x02:
            return "Randomized / Private MAC", "mobile"
        return "", None

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 80:
            return "High"
        if score >= 50:
            return "Medium"
        if score > 0:
            return "Low"
        return "Unverified"

    @classmethod
    def identify_device(
        cls,
        ip_address: str,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        sys_description: Optional[str] = None,
        sys_object_id: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        is_gateway: bool = False,
    ) -> DeviceClassificationResult:
        """
        Evaluates all available telemetry signals to determine manufacturer,
        device_type, confidence_score (0-100), and human-readable evidence reason.
        """
        manufacturer = ""
        device_type = "unknown"
        score = 0
        reasons: List[str] = []
        ports = set(open_ports or [])

        # 1. MAC OUI Vendor Lookup
        mac_vendor, mac_type_hint = cls.lookup_mac_vendor(mac_address)
        if mac_vendor:
            manufacturer = mac_vendor
            score += 35
            reasons.append(f"MAC OUI ({manufacturer})")
            if mac_type_hint:
                device_type = mac_type_hint

        # 2. SNMP sysObjectID Fingerprint (High-confidence authoritative signal)
        if sys_object_id:
            oid_str = sys_object_id.strip().lstrip(".")
            for prefix, (snmp_vendor, snmp_type) in SNMP_ENTERPRISE_MAP.items():
                if oid_str.startswith(prefix):
                    if not manufacturer or manufacturer == "Randomized / Private MAC":
                        manufacturer = snmp_vendor
                    device_type = snmp_type
                    score += 45
                    reasons.append(f"SNMP sysObjectID ({snmp_vendor})")
                    break

        # 3. SNMP sysDescr Analysis (High-confidence authoritative signal)
        if sys_description:
            desc_lower = sys_description.lower()
            score += 40
            if any(k in desc_lower for k in ("palo alto", "fortigate", "fortios", "asa ", "firepower", "opnsense", "pfsense")):
                device_type = "firewall"
                reasons.append("SNMP sysDescr (Firewall OS)")
            elif any(k in desc_lower for k in ("arista", "catalyst", "procurve", "edgeswitch", "nx-os", "eos ")):
                device_type = "switch"
                reasons.append("SNMP sysDescr (Switch OS)")
            elif any(k in desc_lower for k in ("ios xe", "ios-xr", "cisco ios", "routeros", "junos", "vyos", "edgerouter")):
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

        # 4. Hostname / Reverse DNS Heuristics
        if hostname:
            hn = hostname.lower()
            score += 20
            if any(k in hn for k in ("fw", "firewall", "paloalto", "forti")):
                device_type = "firewall"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("core-rtr", "router", "gw", "gateway", "rtr", "mikrotik")):
                device_type = "router"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("sw", "switch", "dist-", "access-sw", "arista")):
                device_type = "switch"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("ap-", "wifi", "wlan", "unifi", "aironet")):
                device_type = "access_point"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("prn", "print", "laserjet", "brother", "canon", "epson")):
                device_type = "printer"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("srv", "server", "prod-", "db-", "sql", "k8s", "node", "esxi", "pve")):
                device_type = "server"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("macbook", "laptop", "thinkpad", "latitude", "xps", "-nb")):
                device_type = "laptop"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("desktop", "workstation", "imac", "optiplex", "-pc", "win11", "win10")):
                device_type = "desktop"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus")):
                device_type = "mobile"
                reasons.append(f"Hostname pattern ({hostname})")
            elif any(k in hn for k in ("nas", "synology", "qnap", "camera", "nvr", "iot")):
                device_type = "appliance"
                reasons.append(f"Hostname pattern ({hostname})")

        # 5. Open TCP Port Signatures
        if ports:
            score += 15
            if ports.intersection({9100, 515, 631}) and device_type in ("unknown", "server"):
                device_type = "printer"
                reasons.append(f"Print service port ({sorted(ports.intersection({9100, 515, 631}))[0]})")
            elif 179 in ports and device_type == "unknown":
                device_type = "router"
                reasons.append("BGP port 179")
            elif ports.intersection({5432, 3306, 27017, 6379, 80, 443, 22}) and device_type == "unknown":
                if not is_gateway:
                    device_type = "server"
                    reasons.append(f"Server ports ({','.join(str(p) for p in sorted(ports)[:3])})")
            elif 3389 in ports and device_type == "unknown":
                device_type = "desktop"
                reasons.append("RDP port 3389")

        # 6. Default Gateway Role Heuristic
        if is_gateway:
            score += 35
            if device_type in ("unknown", "server"):
                device_type = "router"
            reasons.append("Default subnet gateway")

        # Cap confidence score
        if device_type == "unknown":
            final_score = min(score, 35)
        else:
            final_score = min(max(score, 40), 99)

        reason_str = " + ".join(reasons) if reasons else "No identifying MAC OUI, SNMP, hostname, or port telemetry"
        return DeviceClassificationResult(
            device_type=device_type,
            manufacturer=manufacturer,
            confidence_score=final_score,
            confidence_label=cls._confidence_label(final_score),
            reason=reason_str,
        )
