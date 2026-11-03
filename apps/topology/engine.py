"""
NetPulse Network Topology Graph & Auto-Discovery Engine.

Provides:
1. Hierarchical & force-ready graph construction (nodes, edges, effective link health, summary KPIs)
2. Subnet & interface-description auto-discovery (creates discovered NetworkConnection links)
3. Operational link status synchronization with endpoint devices and SNMP interfaces
"""

import ipaddress
import logging
from typing import Optional

from django.db.models import Q

from devices.models import Device
from monitoring.models import NetworkInterface
from .models import NetworkConnection

logger = logging.getLogger("netpulse.topology.engine")


DEVICE_TIER_MAP = {
    Device.DeviceType.FIREWALL: 1,
    Device.DeviceType.ROUTER: 1,
    Device.DeviceType.SWITCH: 2,
    Device.DeviceType.ACCESS_POINT: 2,
    Device.DeviceType.SERVER: 3,
    Device.DeviceType.APPLIANCE: 3,
    Device.DeviceType.PRINTER: 3,
    Device.DeviceType.WORKSTATION: 3,
    Device.DeviceType.DESKTOP: 3,
    Device.DeviceType.LAPTOP: 3,
    Device.DeviceType.MOBILE: 3,
    Device.DeviceType.UNKNOWN: 3,
    Device.DeviceType.OTHER: 3,
}


class TopologyEngine:
    """
    Constructs the interactive NOC network topology graph, synchronizes link
    operational states, and performs automated L2/L3 adjacency discovery.
    """

    @classmethod
    def compute_effective_link_status(cls, connection: NetworkConnection) -> str:
        """
        Determines the effective operational health of a link based on both its
        configured status and the live status of its source/destination devices
        and bound network interfaces.
        """
        src = connection.source_device
        dst = connection.destination_device

        if (
            connection.status == NetworkConnection.Status.DOWN
            or src.status == Device.Status.OFFLINE
            or dst.status == Device.Status.OFFLINE
        ):
            return NetworkConnection.Status.DOWN

        if (
            connection.source_interface
            and connection.source_interface.operational_status == "down"
        ) or (
            connection.destination_interface
            and connection.destination_interface.operational_status == "down"
        ):
            return NetworkConnection.Status.DOWN

        if (
            connection.status == NetworkConnection.Status.DEGRADED
            or src.status == Device.Status.WARNING
            or dst.status == Device.Status.WARNING
        ):
            return NetworkConnection.Status.DEGRADED

        return NetworkConnection.Status.ACTIVE

    @classmethod
    def sync_link_operational_statuses(cls) -> int:
        """
        Synchronizes stored NetworkConnection.status fields with live endpoint
        device and interface states. Returns the number of links updated.
        """
        connections = NetworkConnection.objects.select_related(
            "source_device",
            "destination_device",
            "source_interface",
            "destination_interface",
        ).all()

        updated_count = 0
        for conn in connections:
            effective = cls.compute_effective_link_status(conn)
            if conn.status != effective:
                conn.status = effective
                conn.save(update_fields=["status", "updated_at"])
                updated_count += 1
        return updated_count

    @classmethod
    def auto_discover_subnet_links(cls) -> dict:
        """
        Automatically discovers network links between registered devices using:
        1. Interface description matching (e.g. an interface description mentioning
           another registered device's hostname or IP)
        2. Shared IPv4 /24 subnet adjacency (connects highest-priority core router/switch
           in each /24 subnet to peer devices in the same subnet)

        Never overwrites existing manual links or creates self-loops.
        """
        devices = list(Device.objects.all().order_by("id"))
        if len(devices) < 2:
            return {"created": 0, "total_discovered": 0}

        created_count = 0

        def _link_exists(dev_a_id: int, dev_b_id: int) -> bool:
            return NetworkConnection.objects.filter(
                Q(source_device_id=dev_a_id, destination_device_id=dev_b_id)
                | Q(source_device_id=dev_b_id, destination_device_id=dev_a_id)
            ).exists()

        # 1. Interface description peer matching
        interfaces = NetworkInterface.objects.select_related("device").exclude(description="")
        for iface in interfaces:
            desc_lower = iface.description.lower()
            for peer in devices:
                if peer.id == iface.device_id:
                    continue
                if peer.name.lower() in desc_lower or peer.ip_address in desc_lower:
                    if not _link_exists(iface.device_id, peer.id):
                        if "lldp" in desc_lower:
                            disc_method = NetworkConnection.DiscoveryMethod.LLDP
                        elif "cdp" in desc_lower:
                            disc_method = NetworkConnection.DiscoveryMethod.CDP
                        else:
                            disc_method = NetworkConnection.DiscoveryMethod.INTERFACE_DESC

                        conn = NetworkConnection.objects.create(
                            source_device=iface.device,
                            destination_device=peer,
                            source_interface=iface,
                            connection_type=NetworkConnection.ConnectionType.ETHERNET,
                            link_speed="1 Gbps",
                            is_discovered=True,
                            discovery_method=disc_method,
                            is_confirmed=True,
                            description=f"Confirmed link via interface {iface.interface_name} ({disc_method.upper()})",
                        )
                        conn.status = cls.compute_effective_link_status(conn)
                        conn.save(update_fields=["status"])
                        created_count += 1

        # 2. Shared /24 IPv4 subnet adjacency discovery (Inferred Relationship)
        subnets = {}
        for d in devices:
            try:
                ip_obj = ipaddress.ip_interface(f"{d.ip_address}/24")
                net_key = str(ip_obj.network)
                subnets.setdefault(net_key, []).append(d)
            except ValueError:
                continue

        for net_key, subnet_devices in subnets.items():
            if len(subnet_devices) < 2:
                continue

            # Sort so routers/switches act as hub for the subnet
            subnet_devices.sort(key=lambda dev: (DEVICE_TIER_MAP.get(dev.device_type, 3), dev.id))
            hub = subnet_devices[0]

            for peer in subnet_devices[1:]:
                if hub.id == peer.id or _link_exists(hub.id, peer.id):
                    continue
                conn = NetworkConnection.objects.create(
                    source_device=hub,
                    destination_device=peer,
                    connection_type=NetworkConnection.ConnectionType.ETHERNET,
                    link_speed="1 Gbps",
                    is_discovered=True,
                    discovery_method=NetworkConnection.DiscoveryMethod.SUBNET_INFERRED,
                    is_confirmed=False,
                    description=f"Inferred relationship via shared subnet {net_key}",
                )
                conn.status = cls.compute_effective_link_status(conn)
                conn.save(update_fields=["status"])
                created_count += 1

        total_discovered = NetworkConnection.objects.filter(is_discovered=True).count()
        return {
            "created": created_count,
            "total_discovered": total_discovered,
        }

    @classmethod
    def build_topology_graph(
        cls,
        status_filter: Optional[str] = None,
        connection_type: Optional[str] = None,
        discovery_mode: Optional[str] = None,
    ) -> dict:
        """
        Builds the complete nodes, edges, and summary dictionary consumed by the
        interactive SVG topology visualizer and `/api/topology/graph/` endpoint.
        """
        devices_qs = Device.objects.all().order_by("name")
        if status_filter:
            devices_qs = devices_qs.filter(status=status_filter)

        devices = list(devices_qs)
        device_ids = {d.id for d in devices}

        connections_qs = NetworkConnection.objects.select_related(
            "source_device",
            "destination_device",
            "source_interface",
            "destination_interface",
        ).filter(
            source_device_id__in=device_ids,
            destination_device_id__in=device_ids,
        )

        if connection_type:
            connections_qs = connections_qs.filter(connection_type=connection_type)
        if discovery_mode == "discovered":
            connections_qs = connections_qs.filter(is_discovered=True)
        elif discovery_mode == "manual":
            connections_qs = connections_qs.filter(is_discovered=False)

        connections = list(connections_qs)

        # Count degree (connected edges) per device
        degree_map = {d.id: 0 for d in devices}
        edges = []
        for c in connections:
            degree_map[c.source_device_id] = degree_map.get(c.source_device_id, 0) + 1
            degree_map[c.destination_device_id] = degree_map.get(c.destination_device_id, 0) + 1
            eff_status = cls.compute_effective_link_status(c)

            edges.append({
                "id": c.id,
                "from": c.source_device_id,
                "to": c.destination_device_id,
                "source_name": c.source_device.name,
                "destination_name": c.destination_device.name,
                "label": c.link_speed or c.get_connection_type_display(),
                "type": c.connection_type,
                "type_display": c.get_connection_type_display(),
                "link_speed": c.link_speed or "1 Gbps",
                "status": c.status,
                "effective_status": eff_status,
                "is_discovered": c.is_discovered,
                "discovery_method": c.discovery_method,
                "discovery_method_display": c.get_discovery_method_display(),
                "is_confirmed": c.is_confirmed,
                "source_interface_name": c.source_interface.interface_name if c.source_interface else None,
                "destination_interface_name": c.destination_interface.interface_name if c.destination_interface else None,
                "description": c.description,
            })

        nodes = []
        for d in devices:
            m = d.latest_metric
            nodes.append({
                "id": d.id,
                "label": d.name,
                "ip": d.ip_address,
                "type": d.device_type,
                "type_display": d.get_device_type_display(),
                "tier": DEVICE_TIER_MAP.get(d.device_type, 3),
                "status": d.status,
                "location": d.location or "Unspecified",
                "uptime_percentage": float(d.uptime_percentage),
                "latency": round(m.latency, 1) if (m and m.latency is not None) else None,
                "packet_loss": round(m.packet_loss, 1) if m else 0.0,
                "active_alerts_count": d.alerts.filter(is_resolved=False).count(),
                "interfaces_count": d.interfaces.count(),
                "degree": degree_map.get(d.id, 0),
                "detail_url": f"/devices/{d.id}/",
            })

        summary = {
            "total_nodes": len(nodes),
            "online_nodes": sum(1 for n in nodes if n["status"] == Device.Status.ONLINE),
            "offline_nodes": sum(1 for n in nodes if n["status"] == Device.Status.OFFLINE),
            "warning_nodes": sum(1 for n in nodes if n["status"] == Device.Status.WARNING),
            "isolated_nodes": sum(1 for n in nodes if n["degree"] == 0),
            "total_edges": len(edges),
            "active_edges": sum(1 for e in edges if e["effective_status"] == NetworkConnection.Status.ACTIVE),
            "degraded_edges": sum(1 for e in edges if e["effective_status"] == NetworkConnection.Status.DEGRADED),
            "down_edges": sum(1 for e in edges if e["effective_status"] == NetworkConnection.Status.DOWN),
            "manual_links": sum(1 for e in edges if not e["is_discovered"]),
            "discovered_links": sum(1 for e in edges if e["is_discovered"]),
            "confirmed_links": sum(1 for e in edges if e["is_confirmed"]),
            "inferred_links": sum(1 for e in edges if not e["is_confirmed"]),
        }

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": summary,
        }
