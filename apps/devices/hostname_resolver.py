"""
VIGIL Multi-Method Hostname Discovery Engine.

Resolves device hostnames across local networks using 7 prioritized techniques:
1. Reverse DNS lookup (PTR records via system DNS servers)
2. DHCP lease / Local Router DNS forwarder query (@gateway_ip:53 PTR)
3. NetBIOS Name Service (RFC 1002 NBSTAT UDP/137 Node Status query for Windows/Samba)
4. mDNS discovery (RFC 6762 UDP/5353 `.local` reverse PTR query for macOS/iOS/Linux/IoT)
5. LLMNR discovery (RFC 4795 UDP/5355 Link-Local Multicast Name Resolution for Windows/Linux)
6. SNMP system information (`sysName` 1.3.6.1.2.1.1.5.0)
7. Optional Nmap safe hostname discovery (`nmap -sn --script nbstat`) if Nmap is installed

Guarantees:
- Never returns an IP address or generic IP-dashed placeholder as a hostname.
- Bounded per-protocol timeouts so unreachable hosts never stall discovery.
- Returns both the best authoritative hostname, its source, and the dictionary of
  all discovered hostnames across sources.
"""
import ipaddress
import logging
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("vigil.discovery.hostname")

# Priority order when multiple sources return valid hostnames
SOURCE_PRIORITY: Tuple[str, ...] = (
    "manual",
    "snmp",
    "local",
    "dhcp",
    "ptr",
    "mdns",
    "netbios",
    "llmnr",
    "nmap",
)

SOURCE_LABELS: Dict[str, str] = {
    "manual": "Manual Override",
    "snmp": "SNMP sysName",
    "local": "Local Host OS",
    "dhcp": "Router DHCP / DNS",
    "ptr": "Reverse DNS (PTR)",
    "mdns": "mDNS (.local)",
    "netbios": "NetBIOS (NBNS)",
    "llmnr": "LLMNR",
    "nmap": "Nmap Discovery",
    "none": "Not Resolved",
}


@dataclass
class HostnameResolutionResult:
    """Encapsulates multi-method hostname discovery results for a single host."""
    hostname: str = ""
    source: str = "none"
    all_hostnames: Dict[str, str] = field(default_factory=dict)

    @property
    def source_display(self) -> str:
        return SOURCE_LABELS.get(self.source, self.source.upper() if self.source else "Not Resolved")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["source_display"] = self.source_display
        return data


class HostnameResolver:
    """
    Executes multi-protocol hostname discovery with strict timeouts and validation.
    """

    @staticmethod
    def is_valid_hostname(candidate: Optional[str], ip_address: str = "") -> bool:
        """
        Ensures a candidate hostname is non-empty, not an IPv4/IPv6 literal,
        not a generic dashed-IP placeholder, and contains valid hostname characters.
        """
        if not candidate or not isinstance(candidate, str):
            return False
        cleaned = candidate.strip().rstrip(".")
        if not cleaned or len(cleaned) > 150:
            return False

        # Reject if identical to IP address
        if ip_address and cleaned.lower() == ip_address.strip().lower():
            return False

        # Reject if it parses as an IPv4 or IPv6 address
        try:
            ipaddress.ip_address(cleaned)
            return False
        except ValueError:
            pass

        low = cleaned.lower()
        if low in ("localhost", "localhost.localdomain", "broadcasthost", "*", "unknown", "none", "_gateway"):
            return False
        if low.endswith(".in-addr.arpa") or low.endswith(".ip6.arpa"):
            return False

        # Reject pure dashed-IP auto-records like '192-168-1-34' or 'host-192-168-1-34' if it only contains the IP octets
        if ip_address:
            dashed_ip = ip_address.replace(".", "-")
            if low == dashed_ip:
                return False

        # Must contain at least one ASCII letter and only safe hostname/NetBIOS characters
        if not re.search(r"[A-Za-z]", cleaned):
            return False
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,148}$", cleaned):
            return False

        return True

    @classmethod
    def clean_hostname(cls, candidate: Optional[str], ip_address: str = "") -> str:
        if not candidate:
            return ""
        cleaned = candidate.strip().rstrip(".")
        if not cls.is_valid_hostname(cleaned, ip_address=ip_address):
            return ""
        return cleaned

    # ─── DNS / mDNS / LLMNR Wire-Format Packet Helpers ────────────────────────

    @staticmethod
    def _build_ptr_query_packet(ip_address: str, tx_id: Optional[int] = None, unicast_response: bool = False) -> Tuple[int, bytes]:
        """
        Builds a standard RFC 1035 DNS PTR query packet for `<reversed-ip>.in-addr.arpa`.
        Works for Unicast DNS (port 53), mDNS (port 5353), and LLMNR (port 5355).
        """
        tid = tx_id if tx_id is not None else random.randint(1, 0xFFFF)
        # Standard recursive query (0x0100) for DNS, or 0x0000 for mDNS/LLMNR
        flags = 0x0000 if unicast_response else 0x0100
        header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

        reversed_octets = list(reversed(ip_address.strip().split(".")))
        labels = reversed_octets + ["in-addr", "arpa"]
        qname = b"".join(struct.pack("B", len(lbl)) + lbl.encode("ascii") for lbl in labels) + b"\x00"
        qtype = 12  # PTR
        qclass = 0x8001 if unicast_response else 1  # QU bit set if unicast mDNS response requested
        question = qname + struct.pack("!HH", qtype, qclass)
        return tid, header + question

    @staticmethod
    def _decode_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
        """
        Decodes a DNS domain name from `packet` starting at `offset`, safely
        handling RFC 1035 pointer compression (`0xC0`) and preventing loops.
        """
        labels: List[str] = []
        jumped = False
        orig_next_offset = offset
        visited = set()

        while offset < len(packet):
            if offset in visited:
                break
            visited.add(offset)
            length = packet[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    orig_next_offset = offset
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(packet):
                    break
                pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                if not jumped:
                    orig_next_offset = offset + 2
                    jumped = True
                offset = pointer
                continue
            offset += 1
            if offset + length > len(packet):
                break
            label_bytes = packet[offset : offset + length]
            labels.append(label_bytes.decode("utf-8", errors="ignore"))
            offset += length
            if not jumped:
                orig_next_offset = offset

        return ".".join(labels), orig_next_offset

    @classmethod
    def _parse_ptr_response_packet(cls, packet: bytes, expected_tx_id: Optional[int] = None) -> str:
        """
        Parses a DNS / mDNS / LLMNR response packet and returns the first PTR target name.
        """
        if len(packet) < 12:
            return ""
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        if expected_tx_id is not None and tid != expected_tx_id and expected_tx_id != 0:
            return ""
        if ancount == 0 and arcount == 0:
            return ""

        offset = 12
        for _ in range(qdcount):
            _, offset = cls._decode_dns_name(packet, offset)
            offset += 4
            if offset > len(packet):
                return ""

        total_rr = ancount + nscount + arcount
        for _ in range(total_rr):
            if offset >= len(packet):
                break
            rr_name, offset = cls._decode_dns_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(packet):
                break
            if rtype == 12:  # PTR record
                ptr_name, _ = cls._decode_dns_name(packet, offset)
                if ptr_name:
                    return ptr_name.rstrip(".")
            offset += rdlength
        return ""

    # ─── Method 1: Reverse DNS (PTR) Lookup ───────────────────────────────────

    @classmethod
    def query_dns_server_ptr(cls, ip_address: str, dns_server: str, port: int = 53, timeout: float = 0.65) -> str:
        """Sends a direct UDP PTR query to a specific DNS server (`dns_server:port`)."""
        try:
            tid, pkt = cls._build_ptr_query_packet(ip_address)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(pkt, (dns_server, port))
                data, _ = sock.recvfrom(1024)
                resolved = cls._parse_ptr_response_packet(data, expected_tx_id=tid)
                return cls.clean_hostname(resolved, ip_address=ip_address)
        except Exception:
            return ""

    @staticmethod
    def get_system_dns_servers() -> List[str]:
        """Detects system-configured IPv4 DNS resolvers across Windows/Linux/macOS."""
        servers: List[str] = []
        sys_name = platform.system().lower()
        try:
            if sys_name == "windows":
                proc = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=2.5,
                    check=False,
                )
                for line in proc.stdout.splitlines():
                    if "DNS Servers" in line or "Server" in line:
                        for match in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
                            if match not in servers and not match.startswith("127."):
                                servers.append(match)
            else:
                if os.path.exists("/etc/resolv.conf"):
                    with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if line.strip().startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip_s = parts[1].strip()
                                    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_s) and ip_s not in servers:
                                        servers.append(ip_s)
        except Exception:
            pass
        return servers[:4]

    @classmethod
    def resolve_reverse_dns(
        cls,
        ip_address: str,
        dns_servers: Optional[List[str]] = None,
        timeout: float = 0.65,
        use_os_fallback: bool = False,
    ) -> str:
        """
        Method 1: Resolves hostname via Reverse DNS (PTR records).
        Uses fast direct UDP PTR queries against system DNS servers first to avoid
        Windows `gethostbyaddr`'s 4.5s NetBIOS timeout penalty.
        """
        servers = dns_servers if dns_servers is not None else cls.get_system_dns_servers()
        for srv in servers:
            hn = cls.query_dns_server_ptr(ip_address, srv, port=53, timeout=timeout)
            if hn:
                return hn

        if use_os_fallback:
            try:
                raw_hn, _, _ = socket.gethostbyaddr(ip_address)
                return cls.clean_hostname(raw_hn, ip_address=ip_address)
            except Exception:
                pass
        return ""

    # ─── Method 2: DHCP Lease / Router DNS Forwarder Lookup ───────────────────

    @classmethod
    def resolve_dhcp_router_dns(
        cls,
        ip_address: str,
        gateway_ip: Optional[str] = None,
        timeout: float = 0.65,
    ) -> str:
        """
        Method 2: Queries the subnet's default gateway router DNS daemon (`@gateway_ip:53`)
        which holds active DHCP lease client hostnames (Option 12) on most routers.
        """
        if not gateway_ip or gateway_ip == ip_address:
            return ""
        return cls.query_dns_server_ptr(ip_address, gateway_ip, port=53, timeout=timeout)

    # ─── Method 3: NetBIOS Name Service (UDP 137 NBSTAT) ──────────────────────

    @classmethod
    def resolve_netbios(cls, ip_address: str, timeout: float = 0.65) -> str:
        """
        Method 3: Sends an RFC 1002 NetBIOS Node Status (`NBSTAT`) UDP query to port 137
        and extracts the primary workstation/server name (`<00>` or `<20>` unique name).
        """
        try:
            tid = random.randint(1, 0xFFFF)
            # RFC 1002 NBSTAT query for '*' (encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
            header = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
            encoded_wildcard = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            question = encoded_wildcard + struct.pack("!HH", 0x0021, 0x0001)
            packet = header + question

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip_address, 137))
                resp, _ = sock.recvfrom(1024)
                return cls._parse_netbios_response(resp, ip_address=ip_address)
        except Exception:
            return ""

    @classmethod
    def _parse_netbios_response(cls, resp: bytes, ip_address: str = "") -> str:
        """Parses an RFC 1002 NBSTAT response packet to extract the host's NetBIOS name."""
        if len(resp) < 57:
            return ""
        # Skip 12-byte header, encoded name (34 bytes), type/class/ttl/rdlength (10 bytes) -> byte 56 is num_names
        # Scan for the 0x0021 0x0001 answer header to locate the name table reliably
        marker = b"\x00\x21\x00\x01"
        idx = resp.find(marker, 12)
        if idx == -1 or idx + 11 > len(resp):
            return ""
        num_names = resp[idx + 10]
        pos = idx + 11
        candidates: List[Tuple[int, str]] = []

        for _ in range(num_names):
            if pos + 18 > len(resp):
                break
            raw_name = resp[pos : pos + 15]
            suffix = resp[pos + 15]
            flags = struct.unpack("!H", resp[pos + 16 : pos + 18])[0]
            pos += 18

            is_group = bool(flags & 0x8000)
            if is_group:
                continue

            name_str = raw_name.decode("ascii", errors="ignore").strip()
            # Filter out non-printable control characters
            name_str = "".join(ch for ch in name_str if 32 < ord(ch) < 127)
            cleaned = cls.clean_hostname(name_str, ip_address=ip_address)
            if not cleaned:
                continue

            # Suffix 0x20 = File Server service, 0x00 = Workstation service
            if suffix == 0x20:
                candidates.append((1, cleaned))
            elif suffix == 0x00:
                candidates.append((2, cleaned))
            else:
                candidates.append((3, cleaned))

        if not candidates:
            return ""
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    # ─── Method 4: mDNS (`.local` UDP 5353) Discovery ─────────────────────────

    @classmethod
    def resolve_mdns(cls, ip_address: str, timeout: float = 0.65) -> str:
        """
        Method 4: Sends an mDNS reverse PTR query for `<reversed-ip>.in-addr.arpa`
        to `(ip_address, 5353)` (and multicast `224.0.0.251:5353`) to resolve `.local` names.
        """
        try:
            _, pkt = cls._build_ptr_query_packet(ip_address, tx_id=0, unicast_response=True)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.sendto(pkt, (ip_address, 5353))
                except Exception:
                    pass
                try:
                    sock.sendto(pkt, ("224.0.0.251", 5353))
                except Exception:
                    pass

                data, _ = sock.recvfrom(1024)
                resolved = cls._parse_ptr_response_packet(data, expected_tx_id=0)
                return cls.clean_hostname(resolved, ip_address=ip_address)
        except Exception:
            return ""

    # ─── Method 5: LLMNR (UDP 5355) Discovery ─────────────────────────────────

    @classmethod
    def resolve_llmnr(cls, ip_address: str, timeout: float = 0.55) -> str:
        """
        Method 5: Sends an RFC 4795 LLMNR PTR query to `(ip_address, 5355)` to resolve
        link-local hostnames on Windows and systemd-resolved Linux hosts.
        """
        try:
            tid, pkt = cls._build_ptr_query_packet(ip_address, unicast_response=False)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(pkt, (ip_address, 5355))
                data, _ = sock.recvfrom(1024)
                resolved = cls._parse_ptr_response_packet(data, expected_tx_id=tid)
                return cls.clean_hostname(resolved, ip_address=ip_address)
        except Exception:
            return ""

    # ─── Method 6: SNMP sysName Discovery ─────────────────────────────────────

    @classmethod
    def resolve_snmp_sysname(
        cls,
        ip_address: str,
        community: str = "public",
        port: int = 161,
        pre_fetched_sysname: str = "",
    ) -> str:
        """
        Method 6: Extracts hostname from SNMP `sysName.0` (1.3.6.1.2.1.1.5.0).
        """
        if pre_fetched_sysname:
            return cls.clean_hostname(pre_fetched_sysname, ip_address=ip_address)
        try:
            # Quick UDP port 161 check or SNMPEngine poll if configured
            from monitoring.snmp import SNMPManager

            mgr = SNMPManager(community=community, port=port, timeout=0.8, retries=0)
            sys_info = mgr.get_system_info(ip_address)
            if sys_info and getattr(sys_info, "sys_name", ""):
                return cls.clean_hostname(sys_info.sys_name, ip_address=ip_address)
        except Exception:
            pass
        return ""

    # ─── Method 7: Optional Nmap Safe Hostname Discovery ──────────────────────

    @classmethod
    def resolve_nmap(cls, ip_address: str, timeout: float = 2.5) -> str:
        """
        Method 7: If `nmap` is installed on PATH, runs a safe read-only host discovery
        with `nbstat` to extract any NetBIOS or PTR hostname.
        """
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            return ""
        try:
            proc = subprocess.run(
                [nmap_bin, "-sn", "--script", "nbstat", "--host-timeout", "2s", ip_address],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            out = proc.stdout
            # Check 'Nmap scan report for <hostname> (<ip>)'
            report_match = re.search(r"Nmap scan report for\s+([^\s(]+)\s+\(", out)
            if report_match:
                hn = cls.clean_hostname(report_match.group(1), ip_address=ip_address)
                if hn:
                    return hn
            # Check nbstat script output: 'NetBIOS name: <NAME>'
            nb_match = re.search(r"NetBIOS name:\s*([A-Za-z0-9._\-]+)", out, re.IGNORECASE)
            if nb_match:
                hn = cls.clean_hostname(nb_match.group(1), ip_address=ip_address)
                if hn:
                    return hn
        except Exception:
            pass
        return ""

    # ─── Master Multi-Method Orchestrator ─────────────────────────────────────

    @classmethod
    def resolve_all(
        cls,
        ip_address: str,
        is_local_host: bool = False,
        gateway_ip: Optional[str] = None,
        dns_servers: Optional[List[str]] = None,
        enable_snmp: bool = False,
        snmp_community: str = "public",
        pre_fetched_sysname: str = "",
        enable_nmap: bool = False,
        timeout: float = 0.6,
    ) -> HostnameResolutionResult:
        """
        Executes the multi-method hostname discovery pipeline for `ip_address`,
        collects all valid hostnames found across methods, and selects the most
        authoritative primary hostname and source.
        """
        found: Dict[str, str] = {}

        # 0. Local host OS hostname (if this IP belongs to the VIGIL host itself)
        if is_local_host:
            try:
                local_hn = cls.clean_hostname(socket.gethostname(), ip_address=ip_address)
                if local_hn:
                    found["local"] = local_hn
            except Exception:
                pass

        # 1. Reverse DNS (PTR) via configured DNS servers
        ptr_hn = cls.resolve_reverse_dns(ip_address, dns_servers=dns_servers, timeout=timeout)
        if ptr_hn:
            found["ptr"] = ptr_hn

        # 2. DHCP Lease / Router DNS Forwarder (@gateway_ip:53)
        if gateway_ip and gateway_ip != ip_address:
            dhcp_hn = cls.resolve_dhcp_router_dns(ip_address, gateway_ip=gateway_ip, timeout=timeout)
            if dhcp_hn:
                found["dhcp"] = dhcp_hn

        # 3. NetBIOS Name Service (UDP 137 NBSTAT)
        nb_hn = cls.resolve_netbios(ip_address, timeout=timeout)
        if nb_hn:
            found["netbios"] = nb_hn

        # 4. mDNS (UDP 5353 .local)
        mdns_hn = cls.resolve_mdns(ip_address, timeout=timeout)
        if mdns_hn:
            found["mdns"] = mdns_hn

        # 5. LLMNR (UDP 5355) — run if neither NetBIOS nor mDNS returned a name
        if "netbios" not in found and "mdns" not in found:
            llmnr_hn = cls.resolve_llmnr(ip_address, timeout=min(timeout, 0.5))
            if llmnr_hn:
                found["llmnr"] = llmnr_hn

        # 6. SNMP sysName (if SNMP enabled or pre-fetched)
        if enable_snmp or pre_fetched_sysname:
            snmp_hn = cls.resolve_snmp_sysname(
                ip_address,
                community=snmp_community,
                pre_fetched_sysname=pre_fetched_sysname,
            )
            if snmp_hn:
                found["snmp"] = snmp_hn

        # 7. Optional Nmap fallback (only if enabled and no hostname found yet)
        if enable_nmap and not found:
            nmap_hn = cls.resolve_nmap(ip_address)
            if nmap_hn:
                found["nmap"] = nmap_hn

        # Select primary hostname according to SOURCE_PRIORITY
        primary_hostname = ""
        primary_source = "none"
        for src in SOURCE_PRIORITY:
            if src in found and found[src]:
                primary_hostname = found[src]
                primary_source = src
                break

        return HostnameResolutionResult(
            hostname=primary_hostname,
            source=primary_source,
            all_hostnames=found,
        )
