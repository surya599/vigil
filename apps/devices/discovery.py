"""
VIGIL Phase 3 & Phase 6: Multi-Technique Network Discovery & Inventory Change Detection Engine.

Implements:
1. Authorized subnet CIDR scope validation (never scans public internet ranges)
2. Packet-level Scapy ARP scanning (with Npcap/root) + OS ARP cache (`arp -a` / `ip neigh`)
3. Concurrent ICMP reachability & RTT probing (ICMP failure does not discard ARP-confirmed hosts)
4. Reverse DNS hostname resolution
5. Lightweight TCP service port probing (22, 80, 443, 631, 3389, 9100)
6. Optional SNMPv2c sysDescr / sysObjectID / sysName identification
7. MAC OUI vendor lookup & confidence-scored device classification
8. Automatic Network Change Detection (new, disappeared, returned, IP/MAC/hostname/type changes)
"""
import ipaddress
import logging
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from django.utils import timezone

from devices.identification import DeviceIdentificationEngine
from devices.network_interfaces import NetworkInterfaceDetector
from monitoring.icmp import ICMPChecker

logger = logging.getLogger("vigil.discovery.engine")

COMMON_DISCOVERY_PORTS = (22, 80, 443, 631, 3389, 9100)


@dataclass
class DiscoveredHostRecord:
    """Represents a single discovered network host before/during DB persistence."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: str = ""
    manufacturer: str = ""
    device_type: str = "unknown"
    confidence_score: int = 0
    confidence_label: str = "Unverified"
    classification_reason: str = ""
    discovery_methods: List[str] = field(default_factory=list)
    is_reachable: bool = True
    latency_ms: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)
    sys_description: str = ""
    sys_object_id: str = ""
    subnet_cidr: str = ""
    interface_name: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["discovery_methods_display"] = ", ".join(m.upper() for m in self.discovery_methods)
        return data


class NetworkDiscoveryEngine:
    """
    Executes multi-stage network discovery across an authorized IPv4 subnet CIDR
    and synchronizes findings with the persistent VIGIL inventory & change log.
    """

    def __init__(
        self,
        max_workers: int = 32,
        icmp_timeout: float = 0.6,
        port_timeout: float = 0.25,
        enable_port_probe: bool = True,
        enable_snmp_probe: bool = False,
        snmp_community: str = "public",
    ):
        self.max_workers = max(1, min(max_workers, 64))
        self.icmp_timeout = max(0.1, min(icmp_timeout, 5.0))
        self.port_timeout = max(0.05, min(port_timeout, 2.0))
        self.enable_port_probe = enable_port_probe
        self.enable_snmp_probe = enable_snmp_probe
        self.snmp_community = snmp_community
        self.icmp_checker = ICMPChecker(timeout=self.icmp_timeout)

    @staticmethod
    def try_scapy_arp_scan(cidr: str, timeout: float = 1.2) -> Dict[str, str]:
        """
        Attempts a Layer-2 ARP broadcast scan using Scapy when Npcap (Windows)
        or CAP_NET_RAW (Linux) is available. Fails gracefully to {} otherwise.
        """
        arp_map: Dict[str, str] = {}
        try:
            from scapy.all import ARP, Ether, conf, srp  # type: ignore

            conf.verb = 0
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                timeout=timeout,
                verbose=False,
            )
            for _, rcv in ans:
                ip_addr = getattr(rcv, "psrc", None)
                mac_addr = NetworkInterfaceDetector.normalize_mac(getattr(rcv, "hwsrc", None))
                if ip_addr and mac_addr:
                    arp_map[str(ip_addr)] = mac_addr
        except Exception as exc:
            logger.debug("Scapy Layer-2 ARP scan unavailable (falling back to OS ARP cache): %s", exc)
        return arp_map

    @staticmethod
    def read_os_arp_table(subnet: Optional[ipaddress.IPv4Network] = None) -> Dict[str, str]:
        """
        Reads the operating system ARP neighbor table (`arp -a` on Windows,
        `ip neigh` / `arp -an` on Linux/macOS) and returns {ip_address: normalized_mac}.
        """
        arp_map: Dict[str, str] = {}
        sys_name = platform.system().lower()
        try:
            cmd = ["arp", "-a"] if sys_name == "windows" else ["arp", "-an"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            # Match IPv4 and MAC (XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX)
            pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
            )
            for line in proc.stdout.splitlines():
                match = pattern.search(line)
                if not match:
                    continue
                ip_str, raw_mac = match.group(1), match.group(2)
                norm_mac = NetworkInterfaceDetector.normalize_mac(raw_mac)
                if not norm_mac or norm_mac == "FF:FF:FF:FF:FF:FF":
                    continue
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str)
                    if ip_obj.is_multicast or ip_obj.is_unspecified:
                        continue
                    if subnet and ip_obj not in subnet:
                        continue
                    arp_map[ip_str] = norm_mac
                except ValueError:
                    continue
        except Exception as exc:
            logger.debug("OS ARP table inspection error: %s", exc)
        return arp_map

    @staticmethod
    def resolve_reverse_dns(ip_address: str) -> str:
        """Resolves hostname via reverse DNS PTR lookup without blocking indefinitely."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            if hostname and hostname != ip_address:
                return hostname.rstrip(".")
        except Exception:
            pass
        return ""

    def probe_tcp_ports(self, ip_address: str, ports: Tuple[int, ...] = COMMON_DISCOVERY_PORTS) -> List[int]:
        """Checks a small set of authorized management/service TCP ports on a host."""
        open_ports: List[int] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.port_timeout)
                    if sock.connect_ex((ip_address, port)) == 0:
                        open_ports.append(port)
            except Exception:
                continue
        return open_ports

    def _probe_single_host(self, ip_str: str, probe_ports_on_icmp_fail: bool = False) -> Tuple[str, bool, Optional[float], List[int]]:
        """
        Executes ICMP check (and triggers kernel ARP resolution on local subnet)
        plus optional TCP port check.
        """
        ping_res = self.icmp_checker.ping_host(ip_str, count=1, timeout=self.icmp_timeout)
        if ping_res.is_reachable:
            open_ports = self.probe_tcp_ports(ip_str) if self.enable_port_probe else []
            return ip_str, True, ping_res.avg_latency, open_ports

        if probe_ports_on_icmp_fail and self.enable_port_probe:
            open_ports = self.probe_tcp_ports(ip_str, ports=(80, 443, 22, 3389, 9100))
            return ip_str, bool(open_ports), None, open_ports

        return ip_str, False, None, []

    def scan_subnet(
        self,
        cidr_input: str,
        interface_name: str = "",
        gateway_ip: Optional[str] = None,
        host_ips_override: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        should_stop_callback: Optional[Callable[[], bool]] = None,
    ) -> List[DiscoveredHostRecord]:
        """
        Scans an authorized IPv4 CIDR range using ARP, ICMP, TCP port checks,
        Reverse DNS, and MAC OUI / SNMP identification.
        """
        is_valid, msg, range_info = NetworkInterfaceDetector.validate_authorized_cidr(cidr_input)
        if not is_valid or not range_info:
            raise ValueError(msg)

        normalized_cidr = range_info["network_cidr"]
        net = ipaddress.IPv4Network(normalized_cidr, strict=False)
        inferred_gateway = gateway_ip or range_info["first_host"]

        # Include local interface IPs that belong to this subnet
        local_ifaces = NetworkInterfaceDetector.detect_interfaces(include_loopback=True)
        local_ip_map: Dict[str, Tuple[Optional[str], str]] = {}
        for lif in local_ifaces:
            try:
                if ipaddress.IPv4Address(lif.ipv4_address) in net:
                    local_ip_map[lif.ipv4_address] = (lif.mac_address, lif.name)
                    if not interface_name:
                        interface_name = lif.name
                    if lif.default_gateway and not gateway_ip:
                        inferred_gateway = lif.default_gateway
            except ValueError:
                continue

        if host_ips_override is not None:
            target_ips = [ip for ip in host_ips_override if ipaddress.IPv4Address(ip) in net]
        else:
            hosts = list(net.hosts()) if net.prefixlen <= 30 else [net.network_address]
            target_ips = [str(ip) for ip in hosts]

        total_targets = len(target_ips)

        # Stage 1: Attempt fast Scapy ARP sweep (if Npcap / root is present)
        arp_table = self.try_scapy_arp_scan(normalized_cidr)

        # Stage 2: Concurrent ICMP & TCP probing (also populates OS ARP table for ICMP-blocked hosts)
        probe_results: Dict[str, Tuple[bool, Optional[float], List[int]]] = {}
        completed = 0
        probe_on_fail = total_targets <= 32

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self._probe_single_host, ip, probe_on_fail): ip
                for ip in target_ips
            }
            for future in as_completed(future_to_ip):
                if should_stop_callback and should_stop_callback():
                    break
                ip_str, reachable, latency_ms, open_ports = future.result()
                probe_results[ip_str] = (reachable, latency_ms, open_ports)
                completed += 1
                if progress_callback and (completed % 10 == 0 or completed == total_targets):
                    pct = min(90, int((completed / max(1, total_targets)) * 85))
                    progress_callback(pct, completed, len(arp_table))

        # Stage 3: Read OS ARP cache to catch hosts that answered ARP but blocked ICMP Echo
        os_arp = self.read_os_arp_table(subnet=net)
        for ip_str, mac_addr in os_arp.items():
            if ip_str not in arp_table:
                arp_table[ip_str] = mac_addr

        # Merge all candidate active IPs (ICMP reachable, Port reachable, ARP table present, or local NIC)
        active_ips: Set[str] = set()
        for ip_str, (reachable, _, open_ports) in probe_results.items():
            if reachable or open_ports:
                active_ips.add(ip_str)
        for ip_str in arp_table:
            if host_ips_override is None or ip_str in target_ips:
                active_ips.add(ip_str)
        for ip_str in local_ip_map:
            if host_ips_override is None or ip_str in target_ips:
                active_ips.add(ip_str)

        # Stage 4: Enrich discovered hosts (Reverse DNS, MAC OUI, Device Classification)
        discovered_records: List[DiscoveredHostRecord] = []
        for ip_str in sorted(active_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
            if should_stop_callback and should_stop_callback():
                break

            methods: List[str] = []
            mac_addr = arp_table.get(ip_str)
            if ip_str in local_ip_map and not mac_addr:
                mac_addr = local_ip_map[ip_str][0]

            if mac_addr:
                methods.append("arp")

            icmp_ok, latency_ms, open_ports = probe_results.get(ip_str, (False, None, []))
            if not icmp_ok and not open_ports and self.enable_port_probe:
                # Host was discovered via ARP (blocked ICMP); probe its TCP service ports now
                open_ports = self.probe_tcp_ports(ip_str)
            if icmp_ok and latency_ms is not None:
                methods.append("icmp")
            elif ip_str in local_ip_map:
                methods.append("local")
                if latency_ms is None:
                    latency_ms = 0.5

            if open_ports:
                methods.append("port")

            hostname = self.resolve_reverse_dns(ip_str)
            if not hostname and ip_str in local_ip_map:
                hostname = socket.gethostname()
            if hostname:
                methods.append("dns")

            classification = DeviceIdentificationEngine.identify_device(
                ip_address=ip_str,
                mac_address=mac_addr,
                hostname=hostname,
                open_ports=open_ports,
                is_gateway=(ip_str == inferred_gateway),
            )

            discovered_records.append(
                DiscoveredHostRecord(
                    ip_address=ip_str,
                    mac_address=mac_addr,
                    hostname=hostname,
                    manufacturer=classification.manufacturer,
                    device_type=classification.device_type,
                    confidence_score=classification.confidence_score,
                    confidence_label=classification.confidence_label,
                    classification_reason=classification.reason,
                    discovery_methods=methods or ["arp"],
                    is_reachable=True,
                    latency_ms=round(latency_ms, 2) if latency_ms is not None else None,
                    open_ports=open_ports,
                    subnet_cidr=normalized_cidr,
                    interface_name=interface_name,
                )
            )

        if progress_callback:
            progress_callback(100, total_targets, len(discovered_records))

        return discovered_records

    @classmethod
    def sync_discovered_inventory(
        cls,
        records: List[DiscoveredHostRecord],
        subnet_cidr: str,
        scan_obj=None,
        full_subnet_scan: bool = True,
    ) -> dict:
        """
        Persists DiscoveredHostRecord items into DiscoveredDevice and generates
        NetworkChangeEvent records for:
        - Newly discovered devices ('new_device')
        - Disappeared devices ('device_disappeared')
        - Returning devices ('device_returned')
        - IP address changes for a known MAC ('ip_changed')
        - MAC address changes for a known IP ('mac_changed')
        - Hostname changes ('hostname_changed')
        - Device type classification changes ('type_changed')
        """
        from devices.models import Device, DiscoveredDevice, NetworkChangeEvent
        from alerts.engine import AlertEngine

        now = timezone.now()
        new_count = 0
        updated_count = 0
        changes_count = 0
        seen_ids: Set[int] = set()

        for rec in records:
            methods_str = ",".join(rec.discovery_methods)
            ports_str = ",".join(str(p) for p in rec.open_ports)

            # Check if this host is already a monitored Device
            monitored = Device.objects.filter(ip_address=rec.ip_address).first()
            if not monitored and rec.mac_address:
                monitored = Device.objects.filter(mac_address__iexact=rec.mac_address).first()

            # 1. Check by MAC address first to detect IP address changes
            existing_by_mac = None
            if rec.mac_address:
                existing_by_mac = DiscoveredDevice.objects.filter(
                    mac_address__iexact=rec.mac_address
                ).first()

            existing_by_ip = DiscoveredDevice.objects.filter(ip_address=rec.ip_address).first()

            if existing_by_mac and existing_by_mac.ip_address != rec.ip_address:
                old_ip = existing_by_mac.ip_address
                # Avoid unique IP collision if another stale record had rec.ip_address
                if existing_by_ip and existing_by_ip.pk != existing_by_mac.pk:
                    existing_by_ip.delete()

                existing_by_mac.ip_address = rec.ip_address
                existing_by_mac.last_discovered_at = now
                existing_by_mac.is_reachable = True
                existing_by_mac.latency_ms = rec.latency_ms
                existing_by_mac.discovery_methods = methods_str
                existing_by_mac.open_ports = ports_str
                existing_by_mac.subnet_cidr = subnet_cidr or rec.subnet_cidr
                if scan_obj:
                    existing_by_mac.last_scan = scan_obj
                if monitored:
                    existing_by_mac.monitored_device = monitored
                    existing_by_mac.trust_status = DiscoveredDevice.TrustStatus.MONITORED
                existing_by_mac.save()
                seen_ids.add(existing_by_mac.pk)
                updated_count += 1

                NetworkChangeEvent.objects.create(
                    discovered_device=existing_by_mac,
                    event_type=NetworkChangeEvent.EventType.IP_CHANGED,
                    severity=NetworkChangeEvent.Severity.WARNING,
                    previous_value=old_ip,
                    new_value=rec.ip_address,
                    description=(
                        f"Device with MAC {rec.mac_address} ({existing_by_mac.hostname or existing_by_mac.manufacturer or 'Host'}) "
                        f"changed IP address from {old_ip} to {rec.ip_address}."
                    ),
                )
                changes_count += 1
                continue

            target_dev = existing_by_ip or existing_by_mac
            if target_dev is None:
                # Brand new discovered device!
                trust = (
                    DiscoveredDevice.TrustStatus.MONITORED
                    if monitored
                    else DiscoveredDevice.TrustStatus.UNKNOWN
                )
                target_dev = DiscoveredDevice.objects.create(
                    ip_address=rec.ip_address,
                    mac_address=rec.mac_address,
                    hostname=rec.hostname,
                    manufacturer=rec.manufacturer,
                    device_type=rec.device_type,
                    confidence_score=rec.confidence_score,
                    classification_reason=rec.classification_reason,
                    discovery_methods=methods_str,
                    is_reachable=True,
                    latency_ms=rec.latency_ms,
                    open_ports=ports_str,
                    sys_description=rec.sys_description,
                    sys_object_id=rec.sys_object_id,
                    subnet_cidr=subnet_cidr or rec.subnet_cidr,
                    interface_name=rec.interface_name,
                    trust_status=trust,
                    monitored_device=monitored,
                    last_discovered_at=now,
                    last_scan=scan_obj,
                )
                seen_ids.add(target_dev.pk)
                new_count += 1

                NetworkChangeEvent.objects.create(
                    discovered_device=target_dev,
                    event_type=NetworkChangeEvent.EventType.NEW_DEVICE,
                    severity=NetworkChangeEvent.Severity.INFO,
                    previous_value="",
                    new_value=rec.ip_address,
                    description=(
                        f"Newly discovered {target_dev.get_device_type_display()} at {rec.ip_address} "
                        f"({rec.mac_address or 'MAC unknown'}, {rec.manufacturer or 'Vendor unknown'})."
                    ),
                )
                changes_count += 1
            else:
                # Existing device seen again — check for state transitions
                was_unreachable = not target_dev.is_reachable
                if was_unreachable:
                    NetworkChangeEvent.objects.create(
                        discovered_device=target_dev,
                        event_type=NetworkChangeEvent.EventType.DEVICE_RETURNED,
                        severity=NetworkChangeEvent.Severity.INFO,
                        previous_value="offline",
                        new_value="reachable",
                        description=f"Previously disappeared device {target_dev.ip_address} returned to the network.",
                    )
                    changes_count += 1

                # Detect MAC address change on same IP
                if rec.mac_address and target_dev.mac_address and rec.mac_address.upper() != target_dev.mac_address.upper():
                    old_mac = target_dev.mac_address
                    target_dev.mac_address = rec.mac_address
                    NetworkChangeEvent.objects.create(
                        discovered_device=target_dev,
                        event_type=NetworkChangeEvent.EventType.MAC_CHANGED,
                        severity=NetworkChangeEvent.Severity.WARNING,
                        previous_value=old_mac,
                        new_value=rec.mac_address,
                        description=f"MAC address for {target_dev.ip_address} changed from {old_mac} to {rec.mac_address}.",
                    )
                    changes_count += 1
                elif rec.mac_address and not target_dev.mac_address:
                    target_dev.mac_address = rec.mac_address

                # Detect Hostname change
                if rec.hostname and target_dev.hostname and rec.hostname != target_dev.hostname:
                    old_hn = target_dev.hostname
                    target_dev.hostname = rec.hostname
                    NetworkChangeEvent.objects.create(
                        discovered_device=target_dev,
                        event_type=NetworkChangeEvent.EventType.HOSTNAME_CHANGED,
                        severity=NetworkChangeEvent.Severity.INFO,
                        previous_value=old_hn,
                        new_value=rec.hostname,
                        description=f"Hostname for {target_dev.ip_address} changed from '{old_hn}' to '{rec.hostname}'.",
                    )
                    changes_count += 1
                elif rec.hostname and not target_dev.hostname:
                    target_dev.hostname = rec.hostname

                # Detect Device Type upgrade (if not manually locked and confidence improved)
                if (
                    rec.device_type != "unknown"
                    and target_dev.device_type != rec.device_type
                    and not target_dev.type_manually_set
                ):
                    old_type = target_dev.device_type
                    target_dev.device_type = rec.device_type
                    if old_type != "unknown":
                        NetworkChangeEvent.objects.create(
                            discovered_device=target_dev,
                            event_type=NetworkChangeEvent.EventType.TYPE_CHANGED,
                            severity=NetworkChangeEvent.Severity.INFO,
                            previous_value=old_type,
                            new_value=rec.device_type,
                            description=f"Classification for {target_dev.ip_address} updated from '{old_type}' to '{rec.device_type}'.",
                        )
                        changes_count += 1

                if rec.manufacturer and not target_dev.manufacturer:
                    target_dev.manufacturer = rec.manufacturer
                if rec.confidence_score > target_dev.confidence_score and not target_dev.type_manually_set:
                    target_dev.confidence_score = rec.confidence_score
                    target_dev.classification_reason = rec.classification_reason

                target_dev.is_reachable = True
                target_dev.latency_ms = rec.latency_ms
                target_dev.discovery_methods = methods_str
                target_dev.open_ports = ports_str
                target_dev.last_discovered_at = now
                if subnet_cidr:
                    target_dev.subnet_cidr = subnet_cidr
                if rec.interface_name:
                    target_dev.interface_name = rec.interface_name
                if scan_obj:
                    target_dev.last_scan = scan_obj
                if monitored:
                    target_dev.monitored_device = monitored
                    if target_dev.trust_status == DiscoveredDevice.TrustStatus.UNKNOWN:
                        target_dev.trust_status = DiscoveredDevice.TrustStatus.MONITORED
                target_dev.save()
                seen_ids.add(target_dev.pk)
                updated_count += 1

        # Detect disappeared devices in this subnet (if a full subnet scan was performed)
        disappeared_count = 0
        if full_subnet_scan and subnet_cidr:
            missing_qs = DiscoveredDevice.objects.filter(
                subnet_cidr=subnet_cidr,
                is_reachable=True,
            ).exclude(pk__in=seen_ids)
            for missing_dev in missing_qs:
                missing_dev.is_reachable = False
                missing_dev.save(update_fields=["is_reachable"])
                NetworkChangeEvent.objects.create(
                    discovered_device=missing_dev,
                    event_type=NetworkChangeEvent.EventType.DEVICE_DISAPPEARED,
                    severity=NetworkChangeEvent.Severity.WARNING,
                    previous_value="reachable",
                    new_value="unreachable",
                    description=f"Previously discovered device {missing_dev.ip_address} ({missing_dev.hostname or 'Host'}) was not seen during subnet scan of {subnet_cidr}.",
                )
                disappeared_count += 1
                changes_count += 1

        return {
            "discovered_total": len(records),
            "new_devices": new_count,
            "updated_devices": updated_count,
            "disappeared_devices": disappeared_count,
            "changes_detected": changes_count,
        }
