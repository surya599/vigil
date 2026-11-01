"""
NetPulse Network Topology Views and REST APIs.

Provides:
1. TopologyView (/topology/): Interactive SVG topology visualizer & operator link management
2. topology_graph_api (/api/topology/graph/): Live nodes, edges, effective link health, and summary JSON
3. topology_discover_api (/api/topology/discover/): Automated subnet & interface adjacency link discovery
4. NetworkConnectionViewSet (/api/topology/connections/): CRUD API with Operator/Admin RBAC enforcement
"""

import json

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from accounts.permissions import IsOperatorOrReadOnly
from devices.models import Device
from .engine import TopologyEngine
from .models import NetworkConnection
from .serializers import NetworkConnectionSerializer


class TopologyView(LoginRequiredMixin, TemplateView):
    """
    Interactive Network Topology Visualization.
    Renders devices as nodes and physical/logical links as edges,
    distinguishing manually configured links from discovered links, and allows
    operators to add/delete links or trigger automatic topology discovery.
    """

    template_name = "topology/topology_view.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        status_filter = self.request.GET.get("status")
        conn_type = self.request.GET.get("connection_type")
        discovery_mode = self.request.GET.get("discovery")

        graph = TopologyEngine.build_topology_graph(
            status_filter=status_filter,
            connection_type=conn_type,
            discovery_mode=discovery_mode,
        )
        summary = graph["summary"]

        connections = NetworkConnection.objects.select_related(
            "source_device", "destination_device"
        ).all()

        ctx["topology_data_json"] = json.dumps({
            "nodes": graph["nodes"],
            "edges": graph["edges"],
            "summary": summary,
        })
        ctx["total_nodes"] = summary["total_nodes"]
        ctx["total_edges"] = summary["total_edges"]
        ctx["manual_links"] = summary["manual_links"]
        ctx["discovered_links"] = summary["discovered_links"]
        ctx["active_edges"] = summary["active_edges"]
        ctx["down_edges"] = summary["down_edges"]
        ctx["isolated_nodes"] = summary["isolated_nodes"]
        ctx["connections"] = connections
        ctx["devices"] = Device.objects.order_by("name")
        ctx["connection_type_choices"] = NetworkConnection.ConnectionType.choices
        return ctx

    def post(self, request, *args, **kwargs):
        """Handles operator link creation, link deletion, and auto-discovery."""
        if not (request.user.is_superuser or (hasattr(request.user, "profile") and request.user.profile.is_operator)):
            messages.error(request, "Only operators or administrators can modify network topology links.")
            return redirect("topology:topology-view")

        action = request.POST.get("action")

        if action == "create_connection":
            src_id = request.POST.get("source_device")
            dst_id = request.POST.get("destination_device")
            conn_type = request.POST.get("connection_type", NetworkConnection.ConnectionType.ETHERNET)
            link_speed = request.POST.get("link_speed", "1 Gbps").strip() or "1 Gbps"
            description = request.POST.get("description", "").strip()

            if not src_id or not dst_id:
                messages.error(request, "Both source and destination devices are required.")
                return redirect("topology:topology-view")

            if str(src_id) == str(dst_id):
                messages.error(request, "A device cannot connect directly to itself in topology.")
                return redirect("topology:topology-view")

            src_dev = get_object_or_404(Device, id=int(src_id))
            dst_dev = get_object_or_404(Device, id=int(dst_id))

            try:
                conn = NetworkConnection(
                    source_device=src_dev,
                    destination_device=dst_dev,
                    connection_type=conn_type,
                    link_speed=link_speed,
                    is_discovered=False,
                    description=description,
                )
                conn.status = TopologyEngine.compute_effective_link_status(conn)
                conn.save()
                messages.success(
                    request,
                    f"Created manual topology link: {src_dev.name} → {dst_dev.name} ({link_speed}).",
                )
            except IntegrityError:
                messages.error(
                    request,
                    f"A link from {src_dev.name} to {dst_dev.name} already exists.",
                )

        elif action == "delete_connection":
            conn_id = request.POST.get("connection_id")
            if conn_id and str(conn_id).isdigit():
                conn = get_object_or_404(NetworkConnection, id=int(conn_id))
                label = f"{conn.source_device.name} → {conn.destination_device.name}"
                conn.delete()
                messages.success(request, f"Removed topology link: {label}.")

        elif action == "auto_discover":
            disc_res = TopologyEngine.auto_discover_subnet_links()
            synced = TopologyEngine.sync_link_operational_statuses()
            messages.success(
                request,
                f"Auto-discovery complete: {disc_res['created']} new link(s) discovered, "
                f"{synced} link status(es) synchronized.",
            )

        return redirect("topology:topology-view")


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def topology_graph_api(request):
    """
    Returns live topology graph JSON (nodes, edges, and summary counts)
    with optional ?status=, ?connection_type=, and ?discovery=manual|discovered filters.
    """
    status_filter = request.query_params.get("status")
    conn_type = request.query_params.get("connection_type")
    discovery_mode = request.query_params.get("discovery")

    graph = TopologyEngine.build_topology_graph(
        status_filter=status_filter,
        connection_type=conn_type,
        discovery_mode=discovery_mode,
    )
    return Response(graph, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def topology_discover_api(request):
    """
    Operator/Admin API endpoint that runs automated topology link discovery
    and synchronizes link operational statuses.
    """
    user = request.user
    if not (user.is_superuser or (hasattr(user, "profile") and user.profile.is_operator)):
        return Response(
            {"detail": "Only operators or administrators can trigger topology discovery."},
            status=status.HTTP_403_FORBIDDEN,
        )

    disc_res = TopologyEngine.auto_discover_subnet_links()
    synced = TopologyEngine.sync_link_operational_statuses()
    graph = TopologyEngine.build_topology_graph()

    return Response(
        {
            "status": "success",
            "created_links": disc_res["created"],
            "total_discovered_links": disc_res["total_discovered"],
            "synced_links": synced,
            "summary": graph["summary"],
        },
        status=status.HTTP_200_OK,
    )


class NetworkConnectionViewSet(viewsets.ModelViewSet):
    """
    API for retrieving and managing network connections and topology links.
    Read-only for Viewer role; full CRUD for Operator and Administrator roles.
    """

    queryset = NetworkConnection.objects.all().select_related(
        "source_device",
        "destination_device",
        "source_interface",
        "destination_interface",
    )
    serializer_class = NetworkConnectionSerializer
    permission_classes = [permissions.IsAuthenticated, IsOperatorOrReadOnly]
