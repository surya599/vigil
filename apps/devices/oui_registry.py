"""
VIGIL Authoritative IEEE MAC Address Vendor Registry & LAA/Randomization Analyzer.

Capabilities:
1. Loads the 50,800+ entry IEEE Registration Authority database (MA-L 24-bit,
   MA-M 28-bit, and MA-S 36-bit assignments) from Scapy's Wireshark/IEEE manuf
   dataset plus any local updated registry overlay in `apps/devices/data/ieee_oui_custom.tsv`.
2. Performs longest-prefix matching:
   - 36-bit (MA-S / OUI-36) -> 9 hex characters
   - 28-bit (MA-M)          -> 7 hex characters
   - 24-bit (MA-L / OUI)    -> 6 hex characters
3. Inspects the Locally Administered Address (LAA) bit (bit 1 of the first octet):
   - Distinguishes Globally Administered IEEE MACs from Locally Administered MACs.
   - Identifies known virtual/hypervisor LAA prefixes vs. likely MAC randomization
     (`Randomized / Private MAC (likely)`) without claiming an OUI manufacturer.
4. Separates Network Interface / Wireless Chipset manufacturers (e.g., Intel,
   MediaTek, Lite-On, Realtek, AltoBeam, Broadcom, Qualcomm) from whole-device
   brands so VIGIL never confuses a wireless NIC vendor with the device brand.
"""
import csv
import io
import logging
import os
import re
import urllib.request
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("vigil.discovery.oui")

DATA_DIR = Path(__file__).resolve().parent / "data"
CUSTOM_OUI_FILE = DATA_DIR / "ieee_oui_custom.tsv"

# Known locally administered prefixes used by virtualization/containers (not random mobile MACs)
KNOWN_LAA_VIRTUAL_PREFIXES: Dict[str, Tuple[str, str]] = {
    "525400": ("QEMU / KVM Virtual NIC (Locally Administered)", "server"),
    "0242AC": ("Docker Container Bridge (Locally Administered)", "server"),
    "0A0027": ("VirtualBox Host-Only Adapter (Locally Administered)", " workstation"),
    "02004C": ("Microsoft Loopback Adapter (Locally Administered)", "workstation"),
}

# Component / Wireless Chipset / NIC OEMs whose MAC OUI identifies the network adapter
# rather than the host computer/appliance manufacturer.
NIC_CHIPSET_VENDORS = (
    "intel ",
    "intel corporate",
    "mediatek",
    "liteon",
    "lite-on",
    "realtek",
    "altobeam",
    "broadcom",
    "qualcomm",
    "atheros",
    "azurewave",
    "murata",
    "espressif",
    "cybertan",
    "universal global scientific",
    "hon hai",
    "foxconn",
    "compal",
    "quanta",
    "wistron",
    "pegatron",
    "asix electronics",
    "microchip technology",
    "texas instruments",
    "marvell",
    "ralink",
    "amlogic",
    "rockchip",
    "allwinner",
    "gemtek",
    "arcadyan",
    "sercomm",
    "shenzhen bilian",
    "fn-link",
    "tuya",
)

# Curated mapping from authoritative IEEE Vendor strings to (Estimated Brand, Optional High-Confidence Infrastructure Type)
# Note: Consumer/mobile brands (Apple, Samsung, Xiaomi, Realme, Google, etc.) intentionally have
# device_type_hint=None so VIGIL never guesses "Smartphone" solely from a MAC vendor.
VENDOR_BRAND_AND_INFRA_HINTS: Tuple[Tuple[Tuple[str, ...], str, Optional[str]], ...] = (
    # Enterprise & Carrier Routers / Switches / Firewalls / APs / ONTs
    (("cisco meraki",), "Cisco Meraki", "access_point"),
    (("cisco-linksys", "linksys"), "Linksys", "router"),
    (("cisco systems", "cisco "), "Cisco", None),
    (("arista networks",), "Arista", "switch"),
    (("juniper networks",), "Juniper", "router"),
    (("palo alto networks",), "Palo Alto Networks", "firewall"),
    (("fortinet",), "Fortinet", "firewall"),
    (("sonicwall",), "SonicWall", "firewall"),
    (("ubiquiti",), "Ubiquiti", "access_point"),
    (("mikrotik", "routerboard"), "MikroTik", "router"),
    (("aruba", "hewlett packard enterprise"), "HPE / Aruba", None),
    (("syrotech",), "Syrotech", "router"),
    (("netgear",), "NETGEAR", None),
    (("tp-link",), "TP-Link", None),
    (("d-link",), "D-Link", None),
    (("ruckus",), "Ruckus Wireless", "access_point"),
    (("sagemcom",), "Sagemcom", "router"),
    (("zyxel",), "Zyxel", "router"),
    (("dasannetworks", "dasan"), "DASAN Networks", "router"),
    (("nokia", "alcatel-lucent"), "Nokia", "router"),
    # Virtualization Hypervisors
    (("vmware",), "VMware", "server"),
    (("microsoft corporation",), "Microsoft", None),
    (("xensource", "citrix"), "Citrix Xen", "server"),
    (("proxmox",), "Proxmox", "server"),
    # Printers
    (("brother industries",), "Brother", "printer"),
    (("seiko epson", "epson"), "Epson", "printer"),
    (("canon inc",), "Canon", "printer"),
    (("xerox",), "Xerox", "printer"),
    (("zebra technologies",), "Zebra", "printer"),
    (("ricoh",), "Ricoh", "printer"),
    (("lexmark",), "Lexmark", "printer"),
    (("kyocera",), "Kyocera", "printer"),
    # NAS & Embedded Appliances
    (("synology",), "Synology", "appliance"),
    (("qnap",), "QNAP", "appliance"),
    (("raspberry pi",), "Raspberry Pi", "iot"),
    # Consumer / Enterprise End-User Brands (Type is NOT assumed from MAC alone!)
    (("apple, inc", "apple inc"), "Apple", None),
    (("samsung electronics",), "Samsung", None),
    (("realme",), "Realme", None),
    (("xiaomi",), "Xiaomi", None),
    (("oneplus",), "OnePlus", None),
    (("oppo", "guangdong oppo"), "OPPO", None),
    (("vivo mobile",), " vivo", None),
    (("motorola",), "Motorola", None),
    (("google, inc", "google llc"), "Google", None),
    (("dell inc", "dell "), "Dell", None),
    (("lenovo",), "Lenovo", None),
    (("asustek", "asus"), "ASUS", None),
    (("acer",), "Acer", None),
    (("micro-star", "msi"), "MSI", None),
    (("gigabyte",), "Gigabyte", None),
    (("hewlett packard", "hp inc"), "HP", None),
    (("huawei",), "Huawei", None),
    (("lg electronics",), "LG", None),
    (("sony",), "Sony", None),
    (("amazon technologies",), "Amazon", "iot"),
    (("sonos",), "Sonos", "iot"),
    (("philips lighting", "signify"), "Philips Hue", "iot"),
    (("hikvision",), "Hikvision", "iot"),
    (("dahua",), "Dahua", "iot"),
)


@dataclass(frozen=True)
class MACVendorLookupResult:
    """
    Structured result of an authoritative IEEE MAC address inspection.
    """
    normalized_mac: str
    is_valid: bool
    mac_address_type: str  # 'global', 'locally_administered', 'randomized_likely', 'multicast', 'unknown'
    registered_vendor: str  # Official IEEE registrant name or status ('Locally Administered MAC', 'Unknown Vendor')
    display_vendor: str  # UI-friendly vendor string
    registry_block: str  # 'MA-L (24-bit)', 'MA-M (28-bit)', 'MA-S (36-bit)', 'LAA', or ''
    matched_prefix: str  # e.g. '48:68:4A' or '00:1B:C5:00:1'
    is_chipset_oem: bool  # True if the MAC belongs to a NIC/wireless chip vendor (Intel, MediaTek, AltoBeam, etc.)
    estimated_brand: str  # Device brand only when distinct from generic NIC chip OEM
    default_type_hint: Optional[str]  # Only set for dedicated single-purpose infrastructure/print/hypervisor OUIs

    def to_dict(self) -> dict:
        return asdict(self)


class IEEEOUIRegistry:
    """
    Singleton-backed IEEE MA-L (24-bit), MA-M (28-bit), and MA-S (36-bit) MAC registry.
    """

    _loaded: bool = False
    _ma_l_24: Dict[str, Tuple[str, str]] = {}  # 6 hex chars -> (short, long)
    _ma_m_28: Dict[str, Tuple[str, str]] = {}  # 7 hex chars -> (short, long)
    _ma_s_36: Dict[str, Tuple[str, str]] = {}  # 9 hex chars -> (short, long)

    @classmethod
    def normalize_mac(cls, mac_address: Optional[str]) -> str:
        """
        Normalizes any MAC representation (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX,
        XXXX.XXXX.XXXX, or 12 hex chars) into uppercase 'XX:XX:XX:XX:XX:XX'.
        Returns '' if invalid.
        """
        if not mac_address or not isinstance(mac_address, str):
            return ""
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac_address.strip()).upper()
        if len(cleaned) != 12:
            return ""
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))

    @classmethod
    def ensure_loaded(cls) -> None:
        if cls._loaded:
            return
        cls._load_databases()

    @classmethod
    def _parse_manuf_line(cls, line: str) -> None:
        line = line.strip()
        if not line or line.startswith("#"):
            return
        parts = line.split(None, 2)
        if len(parts) < 2:
            return
        prefix_part = parts[0].upper()
        short_name = parts[1].strip()
        long_name = parts[2].lstrip("#").strip() if len(parts) > 2 else short_name
        long_name = long_name or short_name

        bits = 24
        if "/" in prefix_part:
            prefix_raw, bits_str = prefix_part.split("/", 1)
            try:
                bits = int(bits_str)
            except ValueError:
                bits = 24
        else:
            prefix_raw = prefix_part

        hex_digits = re.sub(r"[^0-9A-F]", "", prefix_raw)
        if bits == 36 and len(hex_digits) >= 9:
            cls._ma_s_36[hex_digits[:9]] = (short_name, long_name)
        elif bits == 28 and len(hex_digits) >= 7:
            cls._ma_m_28[hex_digits[:7]] = (short_name, long_name)
        elif len(hex_digits) >= 6:
            cls._ma_l_24[hex_digits[:6]] = (short_name, long_name)

    @classmethod
    def _load_databases(cls) -> None:
        cls._ma_l_24.clear()
        cls._ma_m_28.clear()
        cls._ma_s_36.clear()

        # 1. Load the 50,825-entry IEEE MA-L / MA-M / MA-S dataset bundled with Scapy
        try:
            from scapy.libs.manuf import DATA as SCAPY_MANUF_DATA  # type: ignore

            for line in SCAPY_MANUF_DATA.splitlines():
                cls._parse_manuf_line(line)
        except Exception as exc:
            logger.warning("Could not load scapy.libs.manuf DATA: %s", exc)

        # 2. Load local updated IEEE registry overlay if present (`apps/devices/data/ieee_oui_custom.tsv`)
        if CUSTOM_OUI_FILE.exists():
            try:
                with open(CUSTOM_OUI_FILE, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        cls._parse_manuf_line(line)
            except Exception as exc:
                logger.warning("Could not load custom IEEE OUI file %s: %s", CUSTOM_OUI_FILE, exc)

        cls._loaded = True
        logger.debug(
            "Loaded IEEE MAC Registry: %d MA-L(/24), %d MA-M(/28), %d MA-S(/36) entries.",
            len(cls._ma_l_24),
            len(cls._ma_m_28),
            len(cls._ma_s_36),
        )

    @classmethod
    def reload_registry(cls) -> dict:
        """Clears in-memory tables and LRU cache and reloads all OUI sources."""
        cls._loaded = False
        cls.lookup.cache_clear()
        cls.ensure_loaded()
        return cls.get_stats()

    @classmethod
    def get_stats(cls) -> dict:
        cls.ensure_loaded()
        return {
            "ma_l_24_count": len(cls._ma_l_24),
            "ma_m_28_count": len(cls._ma_m_28),
            "ma_s_36_count": len(cls._ma_s_36),
            "total_prefixes": len(cls._ma_l_24) + len(cls._ma_m_28) + len(cls._ma_s_36),
            "custom_overlay_path": str(CUSTOM_OUI_FILE),
            "custom_overlay_exists": CUSTOM_OUI_FILE.exists(),
        }

    @staticmethod
    def _classify_vendor_traits(vendor_name: str) -> Tuple[bool, str, Optional[str]]:
        """
        Determines:
        1. Whether `vendor_name` is a NIC/wireless chipset manufacturer (`is_chipset_oem`)
        2. `estimated_brand` (empty string if it's purely a NIC chipset vendor)
        3. `default_type_hint` (only set for dedicated single-role enterprise/print/virtualization vendors)
        """
        if not vendor_name:
            return False, "", None
        v_lower = vendor_name.lower()

        is_chipset = any(k in v_lower for k in NIC_CHIPSET_VENDORS)
        if is_chipset:
            return True, "", None

        for keywords, brand, type_hint in VENDOR_BRAND_AND_INFRA_HINTS:
            if any(k in v_lower for k in keywords):
                return False, brand.strip(), type_hint

        return False, "", None

    @classmethod
    @lru_cache(maxsize=8192)
    def lookup(cls, mac_address: Optional[str]) -> MACVendorLookupResult:
        """
        Performs a full IEEE MA-S (36-bit) -> MA-M (28-bit) -> MA-L (24-bit) lookup
        and Locally Administered Address (LAA) bit analysis.
        """
        norm_mac = cls.normalize_mac(mac_address)
        if not norm_mac:
            return MACVendorLookupResult(
                normalized_mac="",
                is_valid=False,
                mac_address_type="unknown",
                registered_vendor="",
                display_vendor="Unknown Vendor",
                registry_block="",
                matched_prefix="",
                is_chipset_oem=False,
                estimated_brand="",
                default_type_hint=None,
            )

        cls.ensure_loaded()
        hex_str = norm_mac.replace(":", "")
        first_octet = int(hex_str[0:2], 16)

        # Check multicast bit (bit 0 of first octet)
        if first_octet & 0x01:
            return MACVendorLookupResult(
                normalized_mac=norm_mac,
                is_valid=True,
                mac_address_type="multicast",
                registered_vendor="Multicast / Broadcast MAC",
                display_vendor="Multicast MAC",
                registry_block="",
                matched_prefix=norm_mac[:8],
                is_chipset_oem=False,
                estimated_brand="",
                default_type_hint=None,
            )

        # Check Locally Administered Address (LAA) bit (bit 1 of first octet: 0x02)
        if first_octet & 0x02:
            prefix6 = hex_str[:6]
            if prefix6 in KNOWN_LAA_VIRTUAL_PREFIXES:
                v_label, v_type = KNOWN_LAA_VIRTUAL_PREFIXES[prefix6]
                return MACVendorLookupResult(
                    normalized_mac=norm_mac,
                    is_valid=True,
                    mac_address_type="locally_administered",
                    registered_vendor="Locally Administered MAC",
                    display_vendor=v_label,
                    registry_block="LAA",
                    matched_prefix=norm_mac[:8],
                    is_chipset_oem=False,
                    estimated_brand="",
                    default_type_hint=v_type.strip() if v_type else None,
                )

            # Check if the remaining octets look like a manually assigned sequential address
            # (e.g., 02:00:00:00:00:01) vs. high-entropy randomized/private MAC
            tail_hex = hex_str[2:]
            unique_nibbles = len(set(tail_hex))
            is_low_entropy_admin = tail_hex.startswith("0000") or unique_nibbles <= 3

            if is_low_entropy_admin:
                return MACVendorLookupResult(
                    normalized_mac=norm_mac,
                    is_valid=True,
                    mac_address_type="locally_administered",
                    registered_vendor="Locally Administered MAC",
                    display_vendor="Locally Administered MAC",
                    registry_block="LAA",
                    matched_prefix=norm_mac[:8],
                    is_chipset_oem=False,
                    estimated_brand="",
                    default_type_hint=None,
                )

            return MACVendorLookupResult(
                normalized_mac=norm_mac,
                is_valid=True,
                mac_address_type="randomized_likely",
                registered_vendor="Locally Administered MAC",
                display_vendor="Randomized / Private MAC (likely)",
                registry_block="LAA",
                matched_prefix=norm_mac[:8],
                is_chipset_oem=False,
                estimated_brand="",
                default_type_hint=None,
            )

        # Globally Administered Address (U/L bit == 0):
        # 1. Check 36-bit MA-S (9 hex digits)
        key36 = hex_str[:9]
        if key36 in cls._ma_s_36:
            _, full_vendor = cls._ma_s_36[key36]
            is_chip, brand, type_hint = cls._classify_vendor_traits(full_vendor)
            return MACVendorLookupResult(
                normalized_mac=norm_mac,
                is_valid=True,
                mac_address_type="global",
                registered_vendor=full_vendor,
                display_vendor=full_vendor,
                registry_block="MA-S (36-bit)",
                matched_prefix=f"{norm_mac[:13]}/36",
                is_chipset_oem=is_chip,
                estimated_brand=brand,
                default_type_hint=type_hint,
            )

        # 2. Check 28-bit MA-M (7 hex digits)
        key28 = hex_str[:7]
        if key28 in cls._ma_m_28:
            _, full_vendor = cls._ma_m_28[key28]
            is_chip, brand, type_hint = cls._classify_vendor_traits(full_vendor)
            return MACVendorLookupResult(
                normalized_mac=norm_mac,
                is_valid=True,
                mac_address_type="global",
                registered_vendor=full_vendor,
                display_vendor=full_vendor,
                registry_block="MA-M (28-bit)",
                matched_prefix=f"{norm_mac[:10]}/28",
                is_chipset_oem=is_chip,
                estimated_brand=brand,
                default_type_hint=type_hint,
            )

        # 3. Check 24-bit MA-L (6 hex digits)
        key24 = hex_str[:6]
        if key24 in cls._ma_l_24:
            _, full_vendor = cls._ma_l_24[key24]
            is_chip, brand, type_hint = cls._classify_vendor_traits(full_vendor)
            return MACVendorLookupResult(
                normalized_mac=norm_mac,
                is_valid=True,
                mac_address_type="global",
                registered_vendor=full_vendor,
                display_vendor=full_vendor,
                registry_block="MA-L (24-bit)",
                matched_prefix=norm_mac[:8],
                is_chipset_oem=is_chip,
                estimated_brand=brand,
                default_type_hint=type_hint,
            )

        # Unrecognized Global OUI
        return MACVendorLookupResult(
            normalized_mac=norm_mac,
            is_valid=True,
            mac_address_type="global",
            registered_vendor="Unknown Vendor",
            display_vendor="Unknown Vendor",
            registry_block="",
            matched_prefix=norm_mac[:8],
            is_chipset_oem=False,
            estimated_brand="",
            default_type_hint=None,
        )

    @classmethod
    def update_from_ieee_csv(cls, timeout: float = 20.0) -> dict:
        """
        Downloads official IEEE Registration Authority CSV files (MA-L, MA-M, MA-S)
        or Wireshark's consolidated IEEE manuf file and saves them to
        `apps/devices/data/ieee_oui_custom.tsv`, then reloads the registry.
        """
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        ieee_sources = [
            ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 24),
            ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 28),
            ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 36),
        ]
        entries_written = 0
        lines_out = ["# VIGIL Updated IEEE OUI Registry (MA-L /24, MA-M /28, MA-S /36)\n"]

        for label, url, bits in ieee_sources:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "VIGIL-Network-Intelligence/2.0 (IEEE-OUI-Updater)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                reader = csv.reader(io.StringIO(text))
                header = next(reader, None)
                if not header:
                    continue
                for row in reader:
                    if len(row) < 3:
                        continue
                    assignment = re.sub(r"[^0-9A-Fa-f]", "", row[1]).upper()
                    org_name = " ".join(row[2].strip().split())
                    if not assignment or not org_name:
                        continue
                    short_code = re.sub(r"[^A-Za-z0-9]", "", org_name)[:12] or "Vendor"
                    if bits == 24 and len(assignment) >= 6:
                        p = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
                    elif bits == 28 and len(assignment) >= 7:
                        p = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}:{assignment[6:7]}0/28"
                    elif bits == 36 and len(assignment) >= 9:
                        p = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}:{assignment[6:8]}:{assignment[8:9]}0/36"
                    else:
                        continue
                    lines_out.append(f"{p}\t{short_code}\t{org_name}\n")
                    entries_written += 1

        if entries_written > 0:
            with open(CUSTOM_OUI_FILE, "w", encoding="utf-8") as fh:
                fh.writelines(lines_out)

        stats = cls.reload_registry()
        stats["downloaded_entries"] = entries_written
        return stats
