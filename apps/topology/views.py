from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
import json
from rest_framework import viewsets, permissions

from devices.models import Device
from .models import NetworkConnection
from .serializers import NetworkConnectionSerializer


class TopologyView(LoginRequiredMixin, TemplateView):
    """
    Interactive Network Topology Visualization.
    Renders devices as nodes and physical/logical links as edges,
    distinguishing manually configured links from discovered links.
    """
    template_name = "topology/topology_view.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        devices = Device.objects.all()
        connections = NetworkConnection.objects.select_related(
            "source_device", "destination_device"
        ).all()

        nodes = []
        for d in devices:
            nodes.append({
                "id": d.id,
                "label": d.name,
                "ip": d.ip_address,
                "type": d.device_type,
                "type_display": d.get_device_type_display(),
                "status": d.status,
                "location": d.location or "Unspecified",
            })

        edges = []
        for c in connections:
            edges.append({
                "id": c.id,
                "from": c.source_device_id,
                "to": c.destination_device_id,
                "label": c.link_speed or c.get_connection_type_display(),
                "type": c.connection_type,
                "status": c.status,
                "is_discovered": c.is_discovered,
            })

        ctx["topology_data_json"] = json.dumps({"nodes": nodes, "edges": edges})
        ctx["total_nodes"] = len(nodes)
        ctx["total_edges"] = len(edges)
        ctx["manual_links"] = sum(1 for e in edges if not e["is_discovered"])
        ctx["discovered_links"] = sum(1 for e in edges if e["is_discovered"])
        ctx["connections"] = connections
        return ctx


class NetworkConnectionViewSet(viewsets.ModelViewSet):
    """
    API for retrieving and managing network connections and topology nodes.
    """
    queryset = NetworkConnection.objects.all().select_related(
        "source_device",
        "destination_device",
        "source_interface",
        "destination_interface",
    )
    serializer_class = NetworkConnectionSerializer
    permission_classes = [permissions.IsAuthenticated]
