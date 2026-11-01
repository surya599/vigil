"""
NetPulse SNMP Telemetry and Interface Monitoring Engine.

Provides automated polling of network device system metadata (sysDescr, sysUptime, sysName)
and interface performance counters (ifTable / ifXTable) using PySNMP.

Features:
1. Full support for SNMPv2c (community strings) and SNMPv3 (USM SHA/MD5 auth, AES/DES privacy)
2. Dynamic bandwidth calculation (bits per second) using counter differences over elapsed time
3. Robust handling of counter resets, device reboots, and 32-bit/64-bit counter rollover
4. Interface discovery and operational status tracking (UP, DOWN, TESTING, UNKNOWN)
5. Automated alert generation for interface outages and SNMP telemetry failures
6. Thread-safe concurrent multi-device SNMP batch polling
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from django.db import close_old_connections
from django.utils import timezone

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    getCmd,
    walkCmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

logger = logging.getLogger("netpulse.monitoring.snmp")

# Standard MIB-II OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Interface MIB OID prefixes
OID_IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"

# 64-bit High Capacity Counters (ifXTable)
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # in Mbps
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"


@dataclass
class SNMPInterfaceData:
    """Discovered network interface configuration and cumulative traffic counters."""
    index: int
    name: str
    description: str = ""
    mac_address: Optional[str] = None
    admin_status: str = "up"
    oper_status: str = "unknown"
    speed_bps: int = 0
    in_octets: int = 0
    out_octets: int = 0


@dataclass
class SNMPSystemData:
    """Aggregated system telemetry and discovered interface metrics."""
    sys_description: str = ""
    sys_name: str = ""
    sys_uptime: str = ""
    sys_uptime_ticks: int = 0
    interfaces: List[SNMPInterfaceData] = field(default_factory=list)
    is_successful: bool = False
    error_message: Optional[str] = None


class SNMPClient:
    """
    Low-level PySNMP client for SNMPv2c and SNMPv3 communication.
    Executes asynchronous getCmd and walkCmd requests against network hosts.
    """

    def __init__(self, timeout: float = 2.0, retries: int = 1):
        self.timeout = timeout
        self.retries = retries

    def get_auth_data(self, device):
        """Constructs CommunityData (v2c) or UsmUserData (v3) based on device settings."""
        if device.snmp_version == "v3":
            # Map Auth Protocol
            auth_proto = usmNoAuthProtocol
            if device.snmp_v3_auth_protocol == "SHA":
                auth_proto = usmHMACSHAAuthProtocol
            elif device.snmp_v3_auth_protocol == "MD5":
                auth_proto = usmHMACMD5AuthProtocol

            # Map Priv Protocol
            priv_proto = usmNoPrivProtocol
            if device.snmp_v3_priv_protocol == "AES":
                priv_proto = usmAesCfb128Protocol
            elif device.snmp_v3_priv_protocol == "DES":
                priv_proto = usmDESPrivProtocol

            return UsmUserData(
                userName=device.snmp_v3_user or "",
                authKey=device.snmp_v3_auth_key or None,
                authProtocol=auth_proto,
                privKey=device.snmp_v3_priv_key or None,
                privProtocol=priv_proto,
            )
        else:
            # SNMPv2c (default)
            community = device.snmp_community or "public"
            return CommunityData(community, mpModel=1)

    @staticmethod
    def format_uptime(ticks: int) -> str:
        """Formats SNMP TimeTicks (hundredths of a second) into a human-readable duration."""
        total_seconds = int(ticks) / 100.0
        days = int(total_seconds // 86400)
        hours = int((total_seconds % 86400) // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        if days > 0:
            return f"{days}d {hours:02d}h {minutes:02d}m {seconds:02d}s"
        return f"{hours:02d}h {minutes:02d}m {seconds:02d}s"

    @staticmethod
    def format_mac_address(raw_bytes) -> Optional[str]:
        """Converts raw OctetString bytes to a normalized hex MAC address (XX:XX:XX:XX:XX:XX)."""
        if not raw_bytes:
            return None
        b = bytes(raw_bytes)
        if len(b) == 6:
            return ":".join(f"{octet:02X}" for octet in b)
        return None

    @staticmethod
    def parse_oper_status(code: int) -> str:
        """Maps RFC 1213 / RFC 2863 ifOperStatus integer code to status choice."""
        if code == 1:
            return "up"
        elif code == 2:
            return "down"
        elif code == 3:
            return "testing"
        return "unknown"

    @staticmethod
    def parse_admin_status(code: int) -> str:
        """Maps RFC 1213 / RFC 2863 ifAdminStatus integer code to status choice."""
        if code == 1:
            return "up"
        elif code == 2:
            return "down"
        return "unknown"

    async def async_poll_device(self, device, timeout: Optional[float] = None) -> SNMPSystemData:
        """
        Asynchronously queries the target device for system metadata and walks
        the interface tables to retrieve performance metrics.
        """
        snmp_engine = SnmpEngine()
        auth_data = self.get_auth_data(device)
        to = timeout if timeout is not None else self.timeout
        port = device.snmp_port or 161

        try:
            transport = UdpTransportTarget((device.ip_address, port), timeout=to, retries=self.retries)
        except Exception as exc:
            return SNMPSystemData(
                is_successful=False,
                error_message=f"Failed to initialize SNMP transport target: {exc}",
            )

        context_data = ContextData()
        sys_data = SNMPSystemData()

        # 1. Fetch System MIB Information (sysDescr, sysUptime, sysName)
        try:
            error_ind, error_status, error_index, var_binds = await getCmd(
                snmp_engine,
                auth_data,
                transport,
                context_data,
                ObjectType(ObjectIdentity(OID_SYS_DESCR)),
                ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
                ObjectType(ObjectIdentity(OID_SYS_NAME)),
            )

            if error_ind:
                return SNMPSystemData(
                    is_successful=False,
                    error_message=f"SNMP communication error: {error_ind}",
                )
            if error_status:
                return SNMPSystemData(
                    is_successful=False,
                    error_message=f"SNMP agent error: {error_status.prettyPrint()} at {error_index}",
                )

            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                val = var_bind[1]
                if oid_str.startswith(OID_SYS_DESCR):
                    sys_data.sys_description = str(val).strip()
                elif oid_str.startswith(OID_SYS_UPTIME):
                    try:
                        ticks = int(val)
                        sys_data.sys_uptime_ticks = ticks
                        sys_data.sys_uptime = self.format_uptime(ticks)
                    except (ValueError, TypeError):
                        sys_data.sys_uptime = str(val)
                elif oid_str.startswith(OID_SYS_NAME):
                    sys_data.sys_name = str(val).strip()

        except Exception as exc:
            return SNMPSystemData(
                is_successful=False,
                error_message=f"Exception during SNMP system query: {exc}",
            )

        # 2. Walk Interface Table (ifTable / ifXTable)
        interfaces_by_index: Dict[int, SNMPInterfaceData] = {}

        async def _walk_oid(root_oid: str):
            results = []
            try:
                async for err_ind, err_stat, err_idx, v_binds in walkCmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    context_data,
                    ObjectType(ObjectIdentity(root_oid)),
                    lexicographicMode=False,
                ):
                    if err_ind or err_stat:
                        break
                    for vb in v_binds:
                        oid_s = str(vb[0])
                        if oid_s.startswith(root_oid):
                            # Last element of OID is the ifIndex
                            idx_str = oid_s.split(".")[-1]
                            try:
                                idx = int(idx_str)
                                results.append((idx, vb[1]))
                            except ValueError:
                                pass
            except Exception as exc:
                logger.debug("Walk error on %s for %s: %s", root_oid, device.ip_address, exc)
            return results

        # Gather interface attributes
        descr_results = await _walk_oid(OID_IF_DESCR)
        name_results = await _walk_oid(OID_IF_NAME)
        admin_results = await _walk_oid(OID_IF_ADMIN_STATUS)
        oper_results = await _walk_oid(OID_IF_OPER_STATUS)
        speed_results = await _walk_oid(OID_IF_SPEED)
        high_speed_results = await _walk_oid(OID_IF_HIGH_SPEED)
        phys_results = await _walk_oid(OID_IF_PHYS_ADDRESS)
        in_octets_results = await _walk_oid(OID_IF_IN_OCTETS)
        out_octets_results = await _walk_oid(OID_IF_OUT_OCTETS)
        hc_in_octets_results = await _walk_oid(OID_IF_HC_IN_OCTETS)
        hc_out_octets_results = await _walk_oid(OID_IF_HC_OUT_OCTETS)
        alias_results = await _walk_oid(OID_IF_ALIAS)

        # Build interface objects
        for idx, val in descr_results:
            name_val = str(val).strip()
            interfaces_by_index[idx] = SNMPInterfaceData(
                index=idx,
                name=name_val or f"ifIndex-{idx}",
                description=name_val,
            )

        # Overlay ifName from ifXTable if available
        for idx, val in name_results:
            if idx in interfaces_by_index and str(val).strip():
                interfaces_by_index[idx].name = str(val).strip()
            elif idx not in interfaces_by_index:
                interfaces_by_index[idx] = SNMPInterfaceData(
                    index=idx,
                    name=str(val).strip(),
                )

        # Admin status
        for idx, val in admin_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].admin_status = self.parse_admin_status(int(val))
                except (ValueError, TypeError):
                    pass

        # Operational status
        for idx, val in oper_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].oper_status = self.parse_oper_status(int(val))
                except (ValueError, TypeError):
                    pass

        # Speed (bps) - prefer ifHighSpeed (Mbps) if non-zero
        for idx, val in speed_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].speed_bps = int(val)
                except (ValueError, TypeError):
                    pass

        for idx, val in high_speed_results:
            if idx in interfaces_by_index:
                try:
                    mbps = int(val)
                    if mbps > 0:
                        interfaces_by_index[idx].speed_bps = mbps * 1_000_000
                except (ValueError, TypeError):
                    pass

        # MAC Address
        for idx, val in phys_results:
            if idx in interfaces_by_index:
                mac = self.format_mac_address(val)
                if mac:
                    interfaces_by_index[idx].mac_address = mac

        # Interface Alias / Description
        for idx, val in alias_results:
            if idx in interfaces_by_index and str(val).strip():
                interfaces_by_index[idx].description = str(val).strip()

        # In/Out Octets: prefer 64-bit HC counters, fallback to 32-bit
        for idx, val in in_octets_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].in_octets = int(val)
                except (ValueError, TypeError):
                    pass

        for idx, val in hc_in_octets_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].in_octets = int(val)
                except (ValueError, TypeError):
                    pass

        for idx, val in out_octets_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].out_octets = int(val)
                except (ValueError, TypeError):
                    pass

        for idx, val in hc_out_octets_results:
            if idx in interfaces_by_index:
                try:
                    interfaces_by_index[idx].out_octets = int(val)
                except (ValueError, TypeError):
                    pass

        sys_data.interfaces = sorted(interfaces_by_index.values(), key=lambda i: i.index)
        sys_data.is_successful = True
        return sys_data

    def poll(self, device, timeout: Optional[float] = None) -> SNMPSystemData:
        """
        Synchronous wrapper around async_poll_device.
        Safe for use inside Django views, management commands, and Celery tasks.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside an already running async loop (e.g. tests or Daphne)
                return asyncio.run_coroutine_threadsafe(
                    self.async_poll_device(device, timeout=timeout), loop
                ).result()
            return loop.run_until_complete(self.async_poll_device(device, timeout=timeout))
        except RuntimeError:
            return asyncio.run(self.async_poll_device(device, timeout=timeout))


class SNMPMonitoringEngine:
    """
    High-level engine that coordinates SNMP polling, computes bandwidth bitrates,
    updates NetworkInterface models, creates InterfaceMetric records, and evaluates
    alerts for interface outages and SNMP collection failures.
    """

    def __init__(self, client: Optional[SNMPClient] = None):
        self.client = client or SNMPClient()

    @staticmethod
    def calculate_bandwidth(
        prev_metric,
        curr_in_bytes: int,
        curr_out_bytes: int,
        delta_t_seconds: float,
    ) -> Tuple[float, float]:
        """
        Calculates incoming and outgoing traffic rate in bits per second (bps).
        Correctly handles:
        1. Normal increment: curr >= prev
        2. 32-bit counter rollover (4,294,967,296)
        3. 64-bit counter rollover (18,446,744,073,709,551,616)
        4. Device reboot or counter reset (curr < prev and not near rollover): returns 0.0 bps
        """
        if delta_t_seconds <= 0 or prev_metric is None:
            return 0.0, 0.0

        prev_in = prev_metric.incoming_bytes
        prev_out = prev_metric.outgoing_bytes

        # Incoming Delta
        if curr_in_bytes >= prev_in:
            delta_in = curr_in_bytes - prev_in
        else:
            # Check 32-bit rollover
            max_32 = 2**32
            max_64 = 2**64
            if prev_in > (max_32 - 100_000_000) and curr_in_bytes < 100_000_000:
                delta_in = max_32 - prev_in + curr_in_bytes
            elif prev_in > (max_64 - 10_000_000_000) and curr_in_bytes < 10_000_000_000:
                delta_in = max_64 - prev_in + curr_in_bytes
            else:
                # Device reboot or counter reset occurred
                logger.info("Counter reset detected on incoming octets (%d -> %d)", prev_in, curr_in_bytes)
                delta_in = 0

        # Outgoing Delta
        if curr_out_bytes >= prev_out:
            delta_out = curr_out_bytes - prev_out
        else:
            max_32 = 2**32
            max_64 = 2**64
            if prev_out > (max_32 - 100_000_000) and curr_out_bytes < 100_000_000:
                delta_out = max_32 - prev_out + curr_out_bytes
            elif prev_out > (max_64 - 10_000_000_000) and curr_out_bytes < 10_000_000_000:
                delta_out = max_64 - prev_out + curr_out_bytes
            else:
                # Device reboot or counter reset occurred
                logger.info("Counter reset detected on outgoing octets (%d -> %d)", prev_out, curr_out_bytes)
                delta_out = 0

        in_bps = round((delta_in * 8.0) / delta_t_seconds, 2)
        out_bps = round((delta_out * 8.0) / delta_t_seconds, 2)
        return in_bps, out_bps

    def poll_device(self, device, timeout: Optional[float] = None) -> SNMPSystemData:
        """
        Conducts an SNMP interrogation on a single device:
        - Updates system description and uptime
        - Synchronizes network interfaces
        - Calculates dynamic bandwidth and writes InterfaceMetric
        - Generates/resolves INTERFACE_DOWN and SNMP_FAILURE alerts
        """
        from alerts.models import Alert
        from monitoring.broadcaster import broadcast_alert_event, broadcast_snmp_update
        from monitoring.models import InterfaceMetric, NetworkInterface

        now = timezone.now()
        data = self.client.poll(device, timeout=timeout)

        # 1. Handle SNMP Collection Failure
        if not data.is_successful:
            logger.warning("SNMP poll failed for '%s' (%s): %s", device.name, device.ip_address, data.error_message)
            # Create SNMP_FAILURE alert if not already active
            active_alert = Alert.objects.filter(
                device=device,
                alert_type=Alert.AlertType.SNMP_FAILURE,
                is_resolved=False,
            ).first()
            if not active_alert:
                new_alert = Alert.objects.create(
                    device=device,
                    alert_type=Alert.AlertType.SNMP_FAILURE,
                    severity=Alert.Severity.WARNING,
                    description=f"SNMP collection failed for '{device.name}' ({device.ip_address}): {data.error_message}",
                    created_at=now,
                )
                broadcast_alert_event(new_alert, event="created")
            broadcast_snmp_update(device, data, total_in_bps=0.0, total_out_bps=0.0)
            return data

        # SNMP Succeeded: Auto-resolve any active SNMP_FAILURE alert
        for alert in Alert.objects.filter(
            device=device,
            alert_type=Alert.AlertType.SNMP_FAILURE,
            is_resolved=False,
        ):
            alert.resolve()

        # 2. Update Device System Attributes
        update_fields = []
        if data.sys_description:
            device.sys_description = data.sys_description
            update_fields.append("sys_description")
        if data.sys_uptime:
            device.sys_uptime = data.sys_uptime
            update_fields.append("sys_uptime")
        if update_fields:
            device.save(update_fields=update_fields)

        # 3. Synchronize Interfaces & Metrics
        device_total_in_bps = 0.0
        device_total_out_bps = 0.0

        for iface_data in data.interfaces:
            # Find or create NetworkInterface
            iface, _ = NetworkInterface.objects.get_or_create(
                device=device,
                interface_name=iface_data.name,
                defaults={
                    "interface_index": iface_data.index,
                    "description": iface_data.description,
                    "mac_address": iface_data.mac_address,
                    "admin_status": iface_data.admin_status,
                    "operational_status": iface_data.oper_status,
                    "speed_bps": iface_data.speed_bps,
                },
            )

            # Check for Interface Status Transitions
            old_oper = iface.operational_status
            new_oper = iface_data.oper_status

            if old_oper == "up" and new_oper == "down":
                # Interface went DOWN: create Critical Alert
                logger.warning("Interface '%s' on '%s' changed to DOWN", iface.interface_name, device.name)
                new_alert = Alert.objects.create(
                    device=device,
                    alert_type=Alert.AlertType.INTERFACE_DOWN,
                    severity=Alert.Severity.CRITICAL,
                    description=(
                        f"Network interface '{iface.interface_name}' on '{device.name}' ({device.ip_address}) "
                        f"transitioned to operational status DOWN."
                    ),
                    created_at=now,
                )
                broadcast_alert_event(new_alert, event="created")
            elif new_oper == "up" and old_oper != "up":
                # Interface recovered: resolve any active INTERFACE_DOWN alerts
                for alert in Alert.objects.filter(
                    device=device,
                    alert_type=Alert.AlertType.INTERFACE_DOWN,
                    is_resolved=False,
                    description__icontains=f"'{iface.interface_name}'",
                ):
                    alert.resolve()

            # Update interface properties
            iface.interface_index = iface_data.index
            iface.description = iface_data.description
            if iface_data.mac_address:
                iface.mac_address = iface_data.mac_address
            iface.admin_status = iface_data.admin_status
            iface.operational_status = iface_data.oper_status
            iface.speed_bps = iface_data.speed_bps
            iface.save()

            # 4. Calculate Bandwidth Rate
            prev_metric = iface.latest_metric
            if prev_metric:
                delta_t = (now - prev_metric.recorded_at).total_seconds()
            else:
                delta_t = 0.0

            in_bps, out_bps = self.calculate_bandwidth(
                prev_metric=prev_metric,
                curr_in_bytes=iface_data.in_octets,
                curr_out_bytes=iface_data.out_octets,
                delta_t_seconds=delta_t,
            )

            device_total_in_bps += in_bps
            device_total_out_bps += out_bps

            # Record InterfaceMetric
            InterfaceMetric.objects.create(
                interface=iface,
                incoming_bytes=iface_data.in_octets,
                outgoing_bytes=iface_data.out_octets,
                incoming_bps=in_bps,
                outgoing_bps=out_bps,
                recorded_at=now,
            )

            # Evaluate Bandwidth Utilization Threshold (THRESHOLD_EXCEEDED alert)
            from alerts.engine import AlertEngine
            AlertEngine.evaluate_interface_bandwidth(
                device=device,
                interface=iface,
                in_bps=in_bps,
                out_bps=out_bps,
            )

        broadcast_snmp_update(
            device,
            data,
            total_in_bps=device_total_in_bps,
            total_out_bps=device_total_out_bps,
        )
        return data

    def poll_all_snmp_devices(
        self,
        device_ids: Optional[List[int]] = None,
        max_workers: int = 5,
        timeout: float = 2.0,
    ) -> dict:
        """
        Concurrently interrogates all SNMP-enabled devices using a ThreadPoolExecutor.
        Thread-safe: cleans up stale DB connections per worker.
        """
        from devices.models import Device

        qs = Device.objects.filter(monitoring_enabled=True, snmp_enabled=True)
        if device_ids:
            qs = qs.filter(id__in=device_ids)

        devices = list(qs)
        if not devices:
            return {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "devices": [],
                "elapsed_seconds": 0.0,
            }

        start_time = time.time()
        results = []

        def _worker(dev):
            close_old_connections()
            try:
                res = self.poll_device(dev, timeout=timeout)
                return (dev, res)
            except Exception as e:
                logger.error("Error polling SNMP for device '%s': %s", dev.name, e, exc_info=True)
                return (dev, SNMPSystemData(is_successful=False, error_message=str(e)))
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(devices)))) as executor:
            futures = {executor.submit(_worker, d): d for d in devices}
            for fut in as_completed(futures):
                results.append(fut.result())

        elapsed = round(time.time() - start_time, 2)
        successful = sum(1 for _, res in results if res.is_successful)
        failed = sum(1 for _, res in results if not res.is_successful)

        return {
            "total": len(results),
            "successful": successful,
            "failed": failed,
            "results": results,
            "elapsed_seconds": elapsed,
        }
