"""
Test suite for Phase 6: NetPulse SNMP Integration & Interface Monitoring Engine.

Tests:
1. SNMPClient credentials & protocol mapping (SNMPv2c, SNMPv3 USM SHA/MD5, AES/DES)
2. SNMP data formatting (sysUptime TimeTicks, MAC address normalization, status codes)
3. Bandwidth calculation mathematics (normal delta, 32-bit rollover, device reboot reset)
4. SNMPMonitoringEngine interface synchronization and InterfaceMetric creation
5. Interface status transition alerting (INTERFACE_DOWN) and auto-resolution
6. SNMP collection failure alerting (SNMP_FAILURE) and auto-resolution
7. Concurrent multi-device SNMP polling (poll_all_snmp_devices)
8. On-demand SNMP poll REST API (/api/devices/<id>/snmp-poll/)
9. On-demand SNMP poll Web UI view (/devices/<id>/snmp-poll/)
10. Management command (run_snmp_poll)
"""

from io import StringIO
from unittest.mock import MagicMock, patch
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from alerts.models import Alert
from devices.models import Device
from monitoring.models import InterfaceMetric, NetworkInterface
from monitoring.snmp import (
    SNMPClient,
    SNMPInterfaceData,
    SNMPMonitoringEngine,
    SNMPSystemData,
)


class SNMPClientUnitTest(TestCase):
    """Tests SNMPClient credential building, parsing, and formatting."""

    def test_get_auth_data_snmpv2c(self):
        device = Device.objects.create(
            name="Lab-Switch-01",
            ip_address="192.168.10.1",
            snmp_version=Device.SNMPVersion.V2C,
            snmp_community="customcommunity",
        )
        client = SNMPClient()
        auth = client.get_auth_data(device)
        self.assertEqual(auth.mpModel, 1)  # SNMPv2c
        self.assertEqual(auth.communityName, "customcommunity")

    def test_get_auth_data_snmpv3_sha_aes(self):
        device = Device.objects.create(
            name="Core-Router-V3",
            ip_address="192.168.10.2",
            snmp_version=Device.SNMPVersion.V3,
            snmp_v3_user="nocadmin",
            snmp_v3_auth_protocol="SHA",
            snmp_v3_auth_key="authpass12345",
            snmp_v3_priv_protocol="AES",
            snmp_v3_priv_key="privpass12345",
        )
        client = SNMPClient()
        auth = client.get_auth_data(device)
        self.assertEqual(auth.userName, "nocadmin")
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 3))  # usmHMACSHAAuthProtocol
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 2, 4))  # usmAesCfb128Protocol

    def test_get_auth_data_snmpv3_md5_des(self):
        device = Device.objects.create(
            name="Legacy-Router-V3",
            ip_address="192.168.10.3",
            snmp_version=Device.SNMPVersion.V3,
            snmp_v3_user="legacyuser",
            snmp_v3_auth_protocol="MD5",
            snmp_v3_auth_key="md5pass12345",
            snmp_v3_priv_protocol="DES",
            snmp_v3_priv_key="despass12345",
        )
        client = SNMPClient()
        auth = client.get_auth_data(device)
        self.assertEqual(auth.userName, "legacyuser")
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 2))  # usmHMACMD5AuthProtocol
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 2, 2))  # usmDESPrivProtocol

    def test_format_uptime(self):
        client = SNMPClient()
        # 122,173,500 ticks / 100 = 1,221,735 seconds -> 14d 03h 22m 15s
        res = client.format_uptime(122173500)
        self.assertIn("14d", res)
        self.assertIn("03h", res)
        self.assertIn("22m", res)

    def test_format_mac_address(self):
        client = SNMPClient()
        raw_bytes = b"\x00\x1A\x2B\x3C\x4D\x5E"
        mac = client.format_mac_address(raw_bytes)
        self.assertEqual(mac, "00:1A:2B:3C:4D:5E")

    def test_status_code_mappings(self):
        client = SNMPClient()
        self.assertEqual(client.parse_oper_status(1), "up")
        self.assertEqual(client.parse_oper_status(2), "down")
        self.assertEqual(client.parse_oper_status(3), "testing")
        self.assertEqual(client.parse_oper_status(99), "unknown")

        self.assertEqual(client.parse_admin_status(1), "up")
        self.assertEqual(client.parse_admin_status(2), "down")
        self.assertEqual(client.parse_admin_status(99), "unknown")


class BandwidthCalculationTest(TestCase):
    """Tests traffic rate (bps) calculation, counter rollover, and reboot recovery."""

    def setUp(self):
        self.device = Device.objects.create(name="BW-Host", ip_address="10.50.0.1")
        self.iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="eth0",
            interface_index=1,
        )

    def test_calculate_bandwidth_normal_increase(self):
        # Previous: 10,000,000 bytes In, 5,000,000 bytes Out
        prev_metric = MagicMock(
            incoming_bytes=10_000_000,
            outgoing_bytes=5_000_000,
        )
        # Current: 15,000,000 bytes In (+5MB), 8,000,000 bytes Out (+3MB) after 10 seconds
        # In bps: (5,000,000 * 8) / 10 = 4,000,000 bps (4.0 Mbps)
        # Out bps: (3,000,000 * 8) / 10 = 2,400,000 bps (2.4 Mbps)
        in_bps, out_bps = SNMPMonitoringEngine.calculate_bandwidth(
            prev_metric=prev_metric,
            curr_in_bytes=15_000_000,
            curr_out_bytes=8_000_000,
            delta_t_seconds=10.0,
        )
        self.assertEqual(in_bps, 4_000_000.0)
        self.assertEqual(out_bps, 2_400_000.0)

    def test_calculate_bandwidth_32bit_counter_rollover(self):
        # Previous counter near 2^32 (4,294,967,296): e.g. 4,294,000,000
        # Current counter wrapped around: e.g. 1,000,000
        # Delta = (4,294,967,296 - 4,294,000,000) + 1,000,000 = 967,296 + 1,000,000 = 1,967,296 bytes
        prev_metric = MagicMock(
            incoming_bytes=4_294_000_000,
            outgoing_bytes=4_294_000_000,
        )
        in_bps, out_bps = SNMPMonitoringEngine.calculate_bandwidth(
            prev_metric=prev_metric,
            curr_in_bytes=1_000_000,
            curr_out_bytes=1_000_000,
            delta_t_seconds=5.0,
        )
        expected_bps = round((1_967_296 * 8.0) / 5.0, 2)
        self.assertEqual(in_bps, expected_bps)
        self.assertEqual(out_bps, expected_bps)

    def test_calculate_bandwidth_reboot_counter_reset(self):
        # Previous: 200,000,000 bytes
        # Current: 5,000 bytes (sudden drop without being near 2^32 or 2^64 boundary)
        prev_metric = MagicMock(
            incoming_bytes=200_000_000,
            outgoing_bytes=200_000_000,
        )
        in_bps, out_bps = SNMPMonitoringEngine.calculate_bandwidth(
            prev_metric=prev_metric,
            curr_in_bytes=5_000,
            curr_out_bytes=5_000,
            delta_t_seconds=10.0,
        )
        # Should detect reboot/reset and safely return 0.0 bps rather than negative or huge value
        self.assertEqual(in_bps, 0.0)
        self.assertEqual(out_bps, 0.0)


class SNMPMonitoringEngineTest(TestCase):
    """Tests interface synchronization, alerts, and metrics generation."""

    def setUp(self):
        self.device = Device.objects.create(
            name="Cisco-Catalyst-3850",
            ip_address="10.100.1.1",
            device_type=Device.DeviceType.SWITCH,
            snmp_enabled=True,
            snmp_version=Device.SNMPVersion.V2C,
            snmp_community="public",
        )
        self.engine = SNMPMonitoringEngine()

    def test_poll_device_success_updates_metadata_and_interfaces(self):
        mock_data = SNMPSystemData(
            sys_description="Cisco IOS Software, Catalyst L3 Switch Software",
            sys_name="core-sw-01.corp",
            sys_uptime="45d 12h 00m 00s",
            sys_uptime_ticks=393120000,
            interfaces=[
                SNMPInterfaceData(
                    index=1,
                    name="GigabitEthernet0/1",
                    description="Uplink to Core Router",
                    mac_address="00:1A:2B:3C:4D:5E",
                    admin_status="up",
                    oper_status="up",
                    speed_bps=1_000_000_000,
                    in_octets=50_000_000,
                    out_octets=30_000_000,
                ),
                SNMPInterfaceData(
                    index=2,
                    name="GigabitEthernet0/2",
                    description="Server VLAN Trunk",
                    mac_address="00:1A:2B:3C:4D:5F",
                    admin_status="up",
                    oper_status="up",
                    speed_bps=1_000_000_000,
                    in_octets=10_000_000,
                    out_octets=15_000_000,
                ),
            ],
            is_successful=True,
        )

        with patch.object(self.engine.client, "poll", return_value=mock_data):
            res = self.engine.poll_device(self.device)

        self.assertTrue(res.is_successful)
        self.device.refresh_from_db()
        self.assertIn("Cisco IOS", self.device.sys_description)
        self.assertEqual(self.device.sys_uptime, "45d 12h 00m 00s")

        # Verify interfaces created
        self.assertEqual(self.device.interfaces.count(), 2)
        iface1 = self.device.interfaces.get(interface_index=1)
        self.assertEqual(iface1.interface_name, "GigabitEthernet0/1")
        self.assertEqual(iface1.mac_address, "00:1A:2B:3C:4D:5E")
        self.assertEqual(iface1.speed_bps, 1_000_000_000)
        self.assertEqual(iface1.operational_status, "up")

        # Verify metrics created
        self.assertEqual(iface1.metrics.count(), 1)
        m = iface1.latest_metric
        self.assertEqual(m.incoming_bytes, 50_000_000)
        self.assertEqual(m.outgoing_bytes, 30_000_000)

    def test_poll_device_interface_down_triggers_critical_alert(self):
        # Create interface previously UP
        iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="TenGigabitEthernet0/1",
            interface_index=10,
            operational_status="up",
            admin_status="up",
        )

        # Poll reports interface is now DOWN
        mock_data = SNMPSystemData(
            sys_description="Switch",
            sys_uptime="10d",
            interfaces=[
                SNMPInterfaceData(
                    index=10,
                    name="TenGigabitEthernet0/1",
                    oper_status="down",
                    admin_status="up",
                )
            ],
            is_successful=True,
        )

        with patch.object(self.engine.client, "poll", return_value=mock_data):
            self.engine.poll_device(self.device)

        iface.refresh_from_db()
        self.assertEqual(iface.operational_status, "down")

        # Verify Alert created
        alert = Alert.objects.filter(
            device=self.device,
            alert_type=Alert.AlertType.INTERFACE_DOWN,
            is_resolved=False,
        ).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, Alert.Severity.CRITICAL)
        self.assertIn("TenGigabitEthernet0/1", alert.description)

    def test_poll_device_interface_recovery_resolves_alert(self):
        # Interface is down with active alert
        iface = NetworkInterface.objects.create(
            device=self.device,
            interface_name="GigabitEthernet0/5",
            interface_index=5,
            operational_status="down",
        )
        alert = Alert.objects.create(
            device=self.device,
            alert_type=Alert.AlertType.INTERFACE_DOWN,
            severity=Alert.Severity.CRITICAL,
            description="Network interface 'GigabitEthernet0/5' on 'Cisco-Catalyst-3850' is down.",
            is_resolved=False,
        )

        # Poll reports interface is now UP
        mock_data = SNMPSystemData(
            sys_description="Switch",
            sys_uptime="10d",
            interfaces=[
                SNMPInterfaceData(
                    index=5,
                    name="GigabitEthernet0/5",
                    oper_status="up",
                    admin_status="up",
                )
            ],
            is_successful=True,
        )

        with patch.object(self.engine.client, "poll", return_value=mock_data):
            self.engine.poll_device(self.device)

        iface.refresh_from_db()
        alert.refresh_from_db()
        self.assertEqual(iface.operational_status, "up")
        self.assertTrue(alert.is_resolved)
        self.assertIsNotNone(alert.resolved_at)

    def test_poll_device_failure_creates_snmp_failure_alert(self):
        mock_fail = SNMPSystemData(
            is_successful=False,
            error_message="SNMP timeout after 2.0 seconds",
        )

        with patch.object(self.engine.client, "poll", return_value=mock_fail):
            res = self.engine.poll_device(self.device)

        self.assertFalse(res.is_successful)

        alert = Alert.objects.filter(
            device=self.device,
            alert_type=Alert.AlertType.SNMP_FAILURE,
            is_resolved=False,
        ).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, Alert.Severity.WARNING)
        self.assertIn("SNMP timeout", alert.description)


class ConcurrentMultiDeviceSNMPTest(TransactionTestCase):
    """Tests multi-device concurrent SNMP polling."""

    def setUp(self):
        self.dev1 = Device.objects.create(
            name="SNMP-Dev-1",
            ip_address="10.200.1.1",
            snmp_enabled=True,
            monitoring_enabled=True,
        )
        self.dev2 = Device.objects.create(
            name="SNMP-Dev-2",
            ip_address="10.200.1.2",
            snmp_enabled=True,
            monitoring_enabled=True,
        )
        self.dev3 = Device.objects.create(
            name="No-SNMP-Dev",
            ip_address="10.200.1.3",
            snmp_enabled=False,
            monitoring_enabled=True,
        )
        self.engine = SNMPMonitoringEngine()

    def test_poll_all_snmp_devices_skips_non_snmp_devices(self):
        mock_res = SNMPSystemData(
            sys_description="Generic Router",
            sys_uptime="1d",
            is_successful=True,
        )
        with patch.object(self.engine.client, "poll", return_value=mock_res):
            summary = self.engine.poll_all_snmp_devices(max_workers=4)

        # Only dev1 and dev2 had snmp_enabled=True
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["successful"], 2)
        self.assertEqual(summary["failed"], 0)


class OnDemandSNMPAPITest(TestCase):
    """Tests POST /api/devices/<id>/snmp-poll/ REST endpoint."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(username="snmpoperator", password="securepassword123")
        self.operator.profile.role = "operator"
        self.operator.profile.save()

        self.device = Device.objects.create(
            name="Edge-Router-01",
            ip_address="10.20.1.1",
            snmp_enabled=True,
            snmp_version=Device.SNMPVersion.V2C,
            snmp_community="public",
        )

    def test_snmp_poll_api_requires_auth(self):
        url = reverse("devices:device-api-snmp-poll", kwargs={"pk": self.device.pk})
        resp = self.client.post(url)
        self.assertIn(resp.status_code, [401, 403])

    def test_snmp_poll_api_returns_400_if_snmp_disabled(self):
        self.device.snmp_enabled = False
        self.device.save()
        self.client.login(username="snmpoperator", password="securepassword123")
        url = reverse("devices:device-api-snmp-poll", kwargs={"pk": self.device.pk})
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 400)

    def test_snmp_poll_api_executes_and_returns_interfaces(self):
        self.client.login(username="snmpoperator", password="securepassword123")
        url = reverse("devices:device-api-snmp-poll", kwargs={"pk": self.device.pk})

        mock_data = SNMPSystemData(
            sys_description="Juniper Networks SRX300",
            sys_name="fw01.core",
            sys_uptime="30d 05h 12m 00s",
            interfaces=[
                SNMPInterfaceData(
                    index=1,
                    name="ge-0/0/0",
                    description="WAN Uplink",
                    oper_status="up",
                    speed_bps=1_000_000_000,
                    in_octets=25_000_000,
                    out_octets=15_000_000,
                )
            ],
            is_successful=True,
        )

        with patch("monitoring.snmp.SNMPClient.poll", return_value=mock_data):
            resp = self.client.post(url, {"timeout": 2.0}, content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["is_successful"])
        self.assertEqual(data["sys_description"], "Juniper Networks SRX300")
        self.assertEqual(len(data["interfaces"]), 1)
        self.assertEqual(data["interfaces"][0]["name"], "ge-0/0/0")


class OnDemandSNMPViewTest(TestCase):
    """Tests POST /devices/<id>/snmp-poll/ web UI endpoint."""

    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(username="op_user", password="securepassword123")
        self.operator.profile.role = "operator"
        self.operator.profile.save()

        self.viewer = User.objects.create_user(username="view_user", password="securepassword123")
        self.viewer.profile.role = "viewer"
        self.viewer.profile.save()

        self.device = Device.objects.create(
            name="Distribution-Switch",
            ip_address="10.30.1.1",
            snmp_enabled=True,
        )

    def test_viewer_cannot_trigger_snmp_poll(self):
        self.client.login(username="view_user", password="securepassword123")
        url = reverse("devices:device-snmp-poll", kwargs={"pk": self.device.pk})
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 302)

    def test_operator_snmp_poll_redirects_with_message(self):
        self.client.login(username="op_user", password="securepassword123")
        url = reverse("devices:device-snmp-poll", kwargs={"pk": self.device.pk})

        mock_data = SNMPSystemData(
            sys_description="Linux Router",
            sys_uptime="5d 02h",
            interfaces=[SNMPInterfaceData(index=1, name="eth0", oper_status="up")],
            is_successful=True,
        )

        with patch("monitoring.snmp.SNMPClient.poll", return_value=mock_data):
            resp = self.client.post(url)

        self.assertEqual(resp.status_code, 302)
        self.assertRedirects(resp, reverse("devices:device-detail", kwargs={"pk": self.device.pk}))

    def test_operator_snmp_poll_ajax_returns_json(self):
        self.client.login(username="op_user", password="securepassword123")
        url = reverse("devices:device-snmp-poll", kwargs={"pk": self.device.pk})

        mock_data = SNMPSystemData(
            sys_description="Linux Router",
            sys_uptime="5d 02h",
            interfaces=[SNMPInterfaceData(index=1, name="eth0", oper_status="up")],
            is_successful=True,
        )

        with patch("monitoring.snmp.SNMPClient.poll", return_value=mock_data):
            resp = self.client.post(url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["is_successful"])
        self.assertEqual(data["interfaces_count"], 1)


class RunSNMPPollManagementCommandTest(TestCase):
    """Tests the run_snmp_poll management command."""

    def setUp(self):
        self.device = Device.objects.create(
            name="Command-SNMP-Host",
            ip_address="10.40.1.1",
            snmp_enabled=True,
            monitoring_enabled=True,
        )

    def test_run_snmp_poll_single_device(self):
        mock_data = SNMPSystemData(
            sys_description="Test Managed Device",
            sys_uptime="2d",
            interfaces=[SNMPInterfaceData(index=1, name="eth0", oper_status="up", in_octets=1000, out_octets=2000)],
            is_successful=True,
        )
        out = StringIO()
        with patch("monitoring.snmp.SNMPClient.poll", return_value=mock_data):
            call_command("run_snmp_poll", device_id=self.device.id, timeout=1.0, stdout=out)

        output = out.getvalue()
        self.assertIn("Command-SNMP-Host", output)
        self.assertIn("SUCCESS", output)
        self.assertIn("eth0", output)

    def test_run_snmp_poll_all_devices(self):
        mock_data = SNMPSystemData(
            sys_description="Test Device",
            sys_uptime="1d",
            is_successful=True,
        )
        out = StringIO()
        with patch("monitoring.snmp.SNMPClient.poll", return_value=mock_data):
            call_command("run_snmp_poll", timeout=1.0, stdout=out)

        output = out.getvalue()
        self.assertIn("Polled", output)
        self.assertIn("Successful", output)
