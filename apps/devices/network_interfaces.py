"""
VIGIL Phase 2: Automatic Network Interface & Subnet CIDR Detection Engine.

Detects all available and active host network interfaces using psutil, socket,
ipaddress, and OS routing table / ipconfig / route inspection.
Computes network CIDR ranges, subnet masks, MAC addresses, and default gateways,
and enforces strict RFC1918 / authorized-subnet scope validation so VIGIL never
scans arbitrary public internet IP ranges.
"""
import ipaddress
import logging
import platform
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from django.conf import settings

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

logger = logging.getLogger("vigil.discovery.interfaces")


# Default RFC 1918 private & local networks permitted for scanning
DEFAULT_AUTHORIZED_SUPERNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Maximum hosts allowed in a single discovery scan subnet (default: /20 = 4094 hosts, covering /24, /23, /22, /21, /20)
DEFAULT_MAX_SCAN_HOSTS = 4096


@dataclass
class DetectedNetworkInterface:
    """Represents a detected host network interface and its IPv4 subnet parameters."""
    name: str
    ipv4_address: str
    subnet_mask: str
    network_cidr: str
    prefix_len: int
    default_gateway: Optional[str] = None
    mac_address: Optional[str] = None
    is_active: bool = True
    is_loopback: bool = False
    is_primary: bool = False
    speed_mbps: int = 0
    mtu: int = 1500
    usable_hosts_count: int = 0
    first_host: Optional[str] = None
    last_host: Optional[str] = None
    recommended_scan_cidr: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class NetworkInterfaceDetector:
    """
    Detects local network interfaces, IPv4 addresses, subnet masks, MAC addresses,
    default gateways, and automatically computes network CIDR ranges.
    """

    @staticmethod
    def normalize_mac(raw_mac: Optional[str]) -> Optional[str]:
        """Normalizes a MAC address string to uppercase XX:XX:XX:XX:XX:XX format."""
        if not raw_mac:
            return None
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", raw_mac)
        if len(cleaned) != 12 or cleaned == "000000000000":
            return None
        pairs = [cleaned[i : i + 2].upper() for i in range(0, 12, 2)]
        return ":".join(pairs)

    @classmethod
    def calculate_network_range(cls, ipv4_address: str, subnet_mask: str) -> dict:
        """
        Calculates network CIDR notation, prefix length, and usable host range
        from an IPv4 address and subnet mask (e.g., 10.0.114.20 + 255.255.255.0 -> 10.0.114.0/24).
        """
        iface = ipaddress.IPv4Interface(f"{ipv4_address}/{subnet_mask}")
        net = iface.network
        num_addresses = net.num_addresses
        if net.prefixlen <= 30:
            usable = max(0, num_addresses - 2)
            first_host = str(net.network_address + 1)
            last_host = str(net.broadcast_address - 1)
        elif net.prefixlen == 31:
            usable = 2
            first_host = str(net.network_address)
            last_host = str(net.broadcast_address)
        else:
            usable = 1
            first_host = str(net.network_address)
            last_host = str(net.network_address)

        return {
            "ipv4_address": str(iface.ip),
            "subnet_mask": str(net.netmask),
            "network_cidr": str(net),
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address),
            "prefix_len": net.prefixlen,
            "usable_hosts_count": usable,
            "first_host": first_host,
            "last_host": last_host,
        }

    @classmethod
    def get_primary_outbound_ip(cls) -> Optional[str]:
        """Determines the primary outbound local IPv4 address via a non-transmitting UDP socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None

    @classmethod
    def detect_gateways_by_ip(cls) -> Dict[str, str]:
        """
        Inspects OS routing table / ipconfig to map local interface IPv4 addresses
        (or subnets) to their configured default gateway IPv4 address.
        """
        gateways: Dict[str, str] = {}
        sys_name = platform.system().lower()
        try:
            if sys_name == "windows":
                proc = subprocess.run(
                    ["route", "print", "-4"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                # Match lines: 0.0.0.0   0.0.0.0   <gateway_ip>   <interface_ip>   <metric>
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        gw_ip, iface_ip = parts[2], parts[3]
                        try:
                            ipaddress.IPv4Address(gw_ip)
                            ipaddress.IPv4Address(iface_ip)
                            gateways[iface_ip] = gw_ip
                        except ValueError:
                            continue
            else:
                proc = subprocess.run(
                    ["ip", "-4", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                for line in proc.stdout.splitlines():
                    # Example: default via 10.0.114.1 dev eth0 proto dhcp src 10.0.114.20 metric 100
                    gw_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", line)
                    src_match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", line)
                    dev_match = re.search(r"dev\s+(\S+)", line)
                    if gw_match:
                        gw_ip = gw_match.group(1)
                        if src_match:
                            gateways[src_match.group(1)] = gw_ip
                        if dev_match:
                            gateways[dev_match.group(1)] = gw_ip
        except Exception as exc:
            logger.debug("Gateway detection fallback triggered: %s", exc)
        return gateways

    @classmethod
    def detect_interfaces(cls, include_loopback: bool = False, active_only: bool = False) -> List[DetectedNetworkInterface]:
        """
        Enumerates all network interfaces on the host system, collecting:
        - Interface name
        - Active status, speed, and MTU
        - IPv4 address, subnet mask, and calculated CIDR range
        - MAC address
        - Default gateway (or inferred .1 gateway heuristic if OS table omits it)
        """
        primary_ip = cls.get_primary_outbound_ip()
        gateway_map = cls.detect_gateways_by_ip()
        detected: List[DetectedNetworkInterface] = []

        if psutil is not None:
            addrs_map = psutil.net_if_addrs()
            stats_map = psutil.net_if_stats()

            for iface_name, snic_list in addrs_map.items():
                stat = stats_map.get(iface_name)
                is_up = bool(stat.isup) if stat else True
                speed_mbps = int(stat.speed) if (stat and stat.speed) else 0
                mtu = int(stat.mtu) if (stat and stat.mtu) else 1500

                if active_only and not is_up:
                    continue

                mac_addr = None
                for snic in snic_list:
                    family_name = getattr(snic.family, "name", "")
                    if family_name in ("AF_LINK", "AF_PACKET") or getattr(snic, "family", None) == getattr(psutil, "AF_LINK", -1):
                        mac_addr = cls.normalize_mac(snic.address)
                        if mac_addr:
                            break

                for snic in snic_list:
                    if snic.family == socket.AF_INET and snic.address:
                        ip_str = snic.address
                        netmask_str = snic.netmask or "255.255.255.0"
                        try:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                        except ValueError:
                            continue

                        is_loop = ip_obj.is_loopback
                        if is_loop and not include_loopback:
                            continue

                        try:
                            calc = cls.calculate_network_range(ip_str, netmask_str)
                        except ValueError:
                            continue

                        gw = gateway_map.get(ip_str) or gateway_map.get(iface_name)
                        if not gw and not is_loop and calc["prefix_len"] <= 30:
                            # Infer standard first-usable gateway if within same subnet
                            gw = calc["first_host"]

                        is_primary = (ip_str == primary_ip)
                        rec_cidr = calc["network_cidr"]
                        if calc["prefix_len"] < 20:
                            rec_cidr = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                        detected.append(
                            DetectedNetworkInterface(
                                name=iface_name,
                                ipv4_address=ip_str,
                                subnet_mask=calc["subnet_mask"],
                                network_cidr=calc["network_cidr"],
                                prefix_len=calc["prefix_len"],
                                default_gateway=gw,
                                mac_address=mac_addr,
                                is_active=is_up,
                                is_loopback=is_loop,
                                is_primary=is_primary,
                                speed_mbps=speed_mbps,
                                mtu=mtu,
                                usable_hosts_count=calc["usable_hosts_count"],
                                first_host=calc["first_host"],
                                last_host=calc["last_host"],
                                recommended_scan_cidr=rec_cidr,
                            )
                        )
        else:
            # Fallback if psutil is unavailable
            fallback_ip = primary_ip or "127.0.0.1"
            calc = cls.calculate_network_range(fallback_ip, "255.255.255.0")
            detected.append(
                DetectedNetworkInterface(
                    name="eth0",
                    ipv4_address=fallback_ip,
                    subnet_mask=calc["subnet_mask"],
                    network_cidr=calc["network_cidr"],
                    prefix_len=calc["prefix_len"],
                    default_gateway=gateway_map.get(fallback_ip) or calc["first_host"],
                    mac_address=None,
                    is_active=True,
                    is_loopback=(fallback_ip == "127.0.0.1"),
                    is_primary=True,
                    usable_hosts_count=calc["usable_hosts_count"],
                    first_host=calc["first_host"],
                    last_host=calc["last_host"],
                )
            )

        # Sort so primary active non-loopback interface appears first
        detected.sort(
            key=lambda item: (
                not item.is_primary,
                not item.is_active,
                item.is_loopback,
                item.name.lower(),
            )
        )
        return detected

    @classmethod
    def get_Authorized_supernets(cls) -> List[ipaddress.IPv4Network]:
        """Returns the list of authorized IPv4 supernets permitted for discovery scans."""
        custom_cidrs = getattr(settings, "AUTHORIZED_SCAN_NETWORKS", None)
        if custom_cidrs:
            nets = []
            for cidr in custom_cidrs:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            if nets:
                return nets
        return DEFAULT_AUTHORIZED_SUPERNETS

    @classmethod
    def validate_authorized_cidr(
        cls,
        cidr_input: str,
        allow_loopback: bool = True,
        max_hosts: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[dict]]:
        """
        Validates a user-supplied CIDR string or IP/mask:
        1. Must be valid IPv4 network or interface notation.
        2. Must never target public internet IP space (must be inside authorized private/local supernets).
        3. Must not exceed maximum scan host count (default 1024 hosts) to prevent accidental DoS.
        """
        if not cidr_input or not str(cidr_input).strip():
            return False, "Network CIDR cannot be empty.", None

        raw = str(cidr_input).strip()
        try:
            # Accept either '10.0.114.0/24' or '10.0.114.20/24' and normalize to network address
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            return False, f"Invalid CIDR notation '{raw}': {exc}", None

        if not isinstance(net, ipaddress.IPv4Network):
            return False, "Only IPv4 CIDR ranges are supported for network discovery.", None

        if net.is_multicast or net.is_unspecified or net.is_reserved:
            return False, f"Network '{net}' is reserved/multicast and cannot be scanned.", None

        if net.is_loopback and not allow_loopback:
            return False, f"Loopback network '{net}' is not permitted in this scan mode.", None

        authorized_supernets = cls.get_Authorized_supernets()
        is_authorized = any(net.subnet_of(supernet) for supernet in authorized_supernets)
        if not is_authorized or net.is_global:
            return (
                False,
                f"Unauthorized scan scope '{net}': Scanning public or non-authorized IP ranges is strictly prohibited.",
                None,
            )

        limit = max_hosts or getattr(settings, "MAX_DISCOVERY_SCAN_HOSTS", DEFAULT_MAX_SCAN_HOSTS)
        usable_hosts = max(1, net.num_addresses - 2) if net.prefixlen <= 30 else net.num_addresses
        if usable_hosts > limit:
            return (
                False,
                f"Subnet '{net}' contains {usable_hosts} hosts, exceeding the maximum scan limit of {limit} hosts (use /22 or smaller, e.g. /24).",
                None,
            )

        info = cls.calculate_network_range(str(net.network_address), str(net.netmask))
        return True, "Authorized network CIDR validated.", info
