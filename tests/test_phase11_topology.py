"""
Test suite for Phase 11: Interactive Network Topology Graph Visualization.

Tests:
1. TopologyEngine graph construction: hierarchical tiers, node degree, isolated nodes,
   effective link status computation, and link status synchronization
2. Automated L2/L3 topology discovery: shared /24 IPv4 subnet adjacency and
   interface description peer matching without overwriting manual links
3. Topology REST APIs: /api/topology/graph/, /api/topology/discover/,
   /api/topology/connections/ (self-loop validation & Viewer RBAC enforcement)
4. TopologyView Web UI workflow: manual link creation, link deletion, auto-discovery,
   and multi-layout SVG canvas controls
"""

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import UserProfile
from devices.models import Device
from monitoring.models import NetworkInterface
from topology.engine import TopologyEngine
from topology.models import NetworkConnection


class TopologyEngineGraphTest(TestCase):
    """Tests TopologyEngine graph construction, tiers, degrees, and effective link status."""

    def setUp(self):
        self.router = Device.objects.create(
            name="Core-Router-1",
            ip_address="10.110.1.1",
            device_type=Device.DeviceType.ROUTER,
            status=Device.Status.ONLINE,
        )
        self.switch = Device.objects.create(
            name="Dist-Switch-1",
            ip_address="10.110.1.2",
            device_type=Device.DeviceType.SWITCH,
            status=Device.Status.ONLINE,
        )
        self.server = Device.objects.create(
            name="App-Server-1",
            ip_address="10.110.1.10",
            device_type=Device.DeviceType.SERVER,
            status=Device.Status.OFFLINE,
        )
        self.isolated = Device.objects.create(
            name="Isolated-Printer",
            ip_address="10.110.2.50",
            device_type=Device.DeviceType.WORKSTATION,
            status=Device.Status.ONLINE,
        )

        # Manual fiber link: Router -> Switch (both online => ACTIVE)
        self.link1 = NetworkConnection.objects.create(
            source_device=self.router,
            destination_device=self.switch,
            connection_type=NetworkConnection.ConnectionType.FIBER,
            link_speed="10 Gbps",
            is_discovered=False,
        )
        # Discovered ethernet link: Switch -> Server (server is offline => effective DOWN)
        self.link2 = NetworkConnection.objects.create(
            source_device=self.switch,
            destination_device=self.server,
            connection_type=NetworkConnection.ConnectionType.ETHERNET,
            link_speed="1 Gbps",
            is_discovered=True,
        )

    def test_build_topology_graph_computes_tiers_degrees_and_effective_status(self):
        graph = TopologyEngine.build_topology_graph()
        summary = graph["summary"]

        self.assertEqual(summary["total_nodes"], 4)
        self.assertEqual(summary["isolated_nodes"], 1)
        self.assertEqual(summary["total_edges"], 2)
        self.assertEqual(summary["manual_links"], 1)
        self.assertEqual(summary["discovered_links"], 1)
        self.assertEqual(summary["active_edges"], 1)
        self.assertEqual(summary["down_edges"], 1)

        node_by_name = {n["label"]: n for n in graph["nodes"]}
        self.assertEqual(node_by_name["Core-Router-1"]["tier"], 1)
        self.assertEqual(node_by_name["Dist-Switch-1"]["tier"], 2)
        self.assertEqual(node_by_name["Dist-Switch-1"]["degree"], 2)
        self.assertEqual(node_by_name["App-Server-1"]["tier"], 3)
        self.assertEqual(node_by_name["Isolated-Printer"]["degree"], 0)

    def test_sync_link_operational_statuses_updates_database(self):
        self.assertEqual(self.link2.status, NetworkConnection.Status.ACTIVE)
        updated = TopologyEngine.sync_link_operational_statuses()
        self.assertEqual(updated, 1)
        self.link2.refresh_from_db()
        self.assertEqual(self.link2.status, NetworkConnection.Status.DOWN)

    def test_graph_filtering_by_discovery_mode_and_connection_type(self):
        manual_graph = TopologyEngine.build_topology_graph(discovery_mode="manual")
        self.assertEqual(len(manual_graph["edges"]), 1)
        self.assertFalse(manual_graph["edges"][0]["is_discovered"])

        fiber_graph = TopologyEngine.build_topology_graph(connection_type="fiber")
        self.assertEqual(len(fiber_graph["edges"]), 1)
        self.assertEqual(fiber_graph["edges"][0]["link_speed"], "10 Gbps")


class TopologyAutoDiscoveryTest(TestCase):
    """Tests automated subnet and interface-description topology link discovery."""

    def setUp(self):
        # Subnet 10.111.1.0/24 devices
        self.hub_router = Device.objects.create(
            name="Subnet-Hub-Router",
            ip_address="10.111.1.1",
            device_type=Device.DeviceType.ROUTER,
        )
        self.subnet_sw = Device.objects.create(
            name="Subnet-Switch",
            ip_address="10.111.1.2",
            device_type=Device.DeviceType.SWITCH,
        )
        self.subnet_srv = Device.objects.create(
            name="Subnet-Server",
            ip_address="10.111.1.20",
            device_type=Device.DeviceType.SERVER,
        )
        # Remote WAN device in a different /24 linked via interface description
        self.wan_peer = Device.objects.create(
            name="Remote-WAN-Core",
            ip_address="172.20.5.1",
            device_type=Device.DeviceType.ROUTER,
        )
        NetworkInterface.objects.create(
            device=self.hub_router,
            interface_name="Serial0/0/0",
            interface_index=10,
            description="WAN Uplink to Remote-WAN-Core (172.20.5.1)",
            operational_status="up",
        )

    def test_auto_discover_subnet_links_connects_shared_subnet_and_interface_descriptions(self):
        result = TopologyEngine.auto_discover_subnet_links()
        # Expects 1 interface-description link (Hub -> Remote-WAN-Core) + 2 subnet links (Hub -> Switch, Hub -> Server)
        self.assertEqual(result["created"], 3)
        self.assertEqual(result["total_discovered"], 3)

        # Running a second time is idempotent (0 new duplicates created)
        result2 = TopologyEngine.auto_discover_subnet_links()
        self.assertEqual(result2["created"], 0)
        self.assertEqual(result2["total_discovered"], 3)


class TopologyRESTAPITest(TestCase):
    """Tests /api/topology/graph/, /api/topology/discover/, and /api/topology/connections/."""

    def setUp(self):
        self.operator = User.objects.create_user(username="topo_op", password="Password123!")
        self.viewer = User.objects.create_user(username="topo_viewer", password="Password123!")
        self.viewer.profile.role = UserProfile.Role.VIEWER
        self.viewer.profile.save()

        self.dev1 = Device.objects.create(
            name="API-Rtr-1", ip_address="10.112.1.1", device_type=Device.DeviceType.ROUTER
        )
        self.dev2 = Device.objects.create(
            name="API-Sw-1", ip_address="10.112.1.2", device_type=Device.DeviceType.SWITCH
        )

    def test_topology_graph_api_returns_nodes_edges_and_summary(self):
        client = APIClient()
        client.force_authenticate(user=self.viewer)
        res = client.get(reverse("topology:topology-graph-api"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_nodes"], 2)

    def test_topology_discover_api_runs_for_operator_and_blocks_viewer(self):
        viewer_client = APIClient()
        viewer_client.force_authenticate(user=self.viewer)
        r_forbidden = viewer_client.post(reverse("topology:topology-discover-api"))
        self.assertEqual(r_forbidden.status_code, 403)

        op_client = APIClient()
        op_client.force_authenticate(user=self.operator)
        r_ok = op_client.post(reverse("topology:topology-discover-api"))
        self.assertEqual(r_ok.status_code, 200)
        self.assertEqual(r_ok.json()["created_links"], 1)

    def test_connection_viewset_rejects_self_loop_and_blocks_viewer_writes(self):
        op_client = APIClient()
        op_client.force_authenticate(user=self.operator)
        r_loop = op_client.post(
            "/api/topology/connections/",
            {
                "source_device": self.dev1.id,
                "destination_device": self.dev1.id,
                "connection_type": "ethernet",
            },
            format="json",
        )
        self.assertEqual(r_loop.status_code, 400)

        viewer_client = APIClient()
        viewer_client.force_authenticate(user=self.viewer)
        r_viewer = viewer_client.post(
            "/api/topology/connections/",
            {
                "source_device": self.dev1.id,
                "destination_device": self.dev2.id,
                "connection_type": "fiber",
            },
            format="json",
        )
        self.assertEqual(r_viewer.status_code, 403)


class TopologyWebUIWorkflowTest(TestCase):
    """Tests TopologyView Web UI manual link creation, deletion, and auto-discovery."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(username="ui_topo_op", password="Password123!")
        self.client.force_login(self.operator)

        self.dev1 = Device.objects.create(name="UI-Rtr-1", ip_address="10.113.1.1")
        self.dev2 = Device.objects.create(name="UI-Sw-1", ip_address="10.113.1.2")

    def test_operator_can_create_delete_and_auto_discover_links_via_web_post(self):
        # 1. Create manual connection
        res_create = self.client.post(
            reverse("topology:topology-view"),
            {
                "action": "create_connection",
                "source_device": self.dev1.id,
                "destination_device": self.dev2.id,
                "connection_type": "fiber",
                "link_speed": "10 Gbps",
                "description": "Primary backbone fiber",
            },
        )
        self.assertEqual(res_create.status_code, 302)
        conn = NetworkConnection.objects.get(source_device=self.dev1, destination_device=self.dev2)
        self.assertFalse(conn.is_discovered)
        self.assertEqual(conn.link_speed, "10 Gbps")

        # 2. Delete connection
        res_del = self.client.post(
            reverse("topology:topology-view"),
            {"action": "delete_connection", "connection_id": conn.id},
        )
        self.assertEqual(res_del.status_code, 302)
        self.assertEqual(NetworkConnection.objects.count(), 0)

        # 3. Auto-discover connection (both in 10.113.1.0/24)
        res_disc = self.client.post(
            reverse("topology:topology-view"),
            {"action": "auto_discover"},
        )
        self.assertEqual(res_disc.status_code, 302)
        self.assertEqual(NetworkConnection.objects.filter(is_discovered=True).count(), 1)
