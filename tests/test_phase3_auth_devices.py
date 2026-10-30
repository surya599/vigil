"""
Phase 3 automated tests: Authentication flows, role-based access control,
device management UI (views + forms), and IP address validation.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from accounts.models import UserProfile
from accounts.forms import NetPulseLoginForm, UserRegistrationForm
from devices.models import Device
from devices.forms import DeviceForm

User = get_user_model()


# ─── Authentication Tests ───────────────────────────────────────────────────────

class LoginViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testlogin", password="TestPass99!", email="login@test.local"
        )

    def test_login_page_get(self):
        response = self.client.get("/login/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "NetPulse")

    def test_login_with_valid_credentials_redirects_to_dashboard(self):
        response = self.client.post("/login/", {
            "username": "testlogin",
            "password": "TestPass99!",
        })
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_login_with_wrong_password_returns_form_error(self):
        response = self.client.post("/login/", {
            "username": "testlogin",
            "password": "WrongPassword!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_authenticated_user_redirected_away_from_login(self):
        self.client.login(username="testlogin", password="TestPass99!")
        response = self.client.get("/login/")
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_logout_clears_session(self):
        self.client.login(username="testlogin", password="TestPass99!")
        self.client.post("/logout/")
        response = self.client.get("/dashboard/")
        # Should redirect to login since session is cleared
        self.assertEqual(response.status_code, 302)


class LogoutViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="logouttest", password="LogOut99!")

    def test_get_logout_redirects_to_login(self):
        self.client.login(username="logouttest", password="LogOut99!")
        response = self.client.get("/logout/")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)

    def test_post_logout_clears_authentication(self):
        self.client.login(username="logouttest", password="LogOut99!")
        self.client.post("/logout/")
        self.assertFalse(self.client.session.get("_auth_user_id"))


# ─── Registration Tests ─────────────────────────────────────────────────────────

class RegisterViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(
            username="adminreg", password="Admin99!", email="admin@reg.local"
        )
        self.operator = User.objects.create_user(
            username="opreg", password="Op99!", email="op@reg.local"
        )

    def test_admin_can_access_register_page(self):
        self.client.login(username="adminreg", password="Admin99!")
        response = self.client.get("/register/")
        self.assertEqual(response.status_code, 200)

    def test_operator_cannot_access_register_page(self):
        self.client.login(username="opreg", password="Op99!")
        response = self.client.get("/register/")
        # Redirected away
        self.assertEqual(response.status_code, 302)

    def test_unauthenticated_cannot_access_register(self):
        response = self.client.get("/register/")
        self.assertEqual(response.status_code, 302)

    def test_admin_can_create_new_user(self):
        self.client.login(username="adminreg", password="Admin99!")
        response = self.client.post("/register/", {
            "username": "newoperator",
            "first_name": "New",
            "last_name": "Operator",
            "email": "newop@test.local",
            "password1": "NewOp1234!",
            "password2": "NewOp1234!",
            "role": "operator",
            "department": "NOC",
            "phone_number": "",
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="newoperator").exists())
        new_user = User.objects.get(username="newoperator")
        self.assertEqual(new_user.profile.role, "operator")


# ─── Profile Tests ──────────────────────────────────────────────────────────────

class ProfileViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="profileuser", password="Profile99!", email="profile@test.local"
        )
        self.client.login(username="profileuser", password="Profile99!")

    def test_profile_page_loads(self):
        response = self.client.get("/profile/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "profileuser")

    def test_profile_update(self):
        response = self.client.post("/profile/", {
            "first_name": "Updated",
            "last_name": "User",
            "email": "profile@test.local",
            "department": "NOC Operations",
            "phone_number": "9876543210",
            "email_notifications": "on",
        })
        self.assertRedirects(response, "/profile/", fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Updated")
        self.assertEqual(self.user.profile.department, "NOC Operations")


# ─── Role-Based Access Control Tests ────────────────────────────────────────────

class RoleBasedAccessTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.viewer = User.objects.create_user(username="viewer_user", password="Viewer99!")
        self.viewer.profile.role = UserProfile.Role.VIEWER
        self.viewer.profile.save()

        self.operator = User.objects.create_user(username="operator_user", password="Operator99!")
        self.operator.profile.role = UserProfile.Role.OPERATOR
        self.operator.profile.save()

        self.admin = User.objects.create_superuser(
            username="admin_user", password="Admin99!", email="admin@rbac.local"
        )

    def test_viewer_cannot_add_device(self):
        self.client.login(username="viewer_user", password="Viewer99!")
        response = self.client.get("/devices/add/")
        self.assertEqual(response.status_code, 302)  # Redirected

    def test_operator_can_access_add_device(self):
        self.client.login(username="operator_user", password="Operator99!")
        response = self.client.get("/devices/add/")
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_user_list(self):
        self.client.login(username="admin_user", password="Admin99!")
        response = self.client.get("/users/")
        self.assertEqual(response.status_code, 200)

    def test_operator_cannot_access_user_list(self):
        self.client.login(username="operator_user", password="Operator99!")
        response = self.client.get("/users/")
        self.assertEqual(response.status_code, 302)

    def test_dashboard_accessible_to_all_authenticated_users(self):
        for username, password in [
            ("viewer_user", "Viewer99!"),
            ("operator_user", "Operator99!"),
            ("admin_user", "Admin99!"),
        ]:
            self.client.login(username=username, password=password)
            response = self.client.get("/dashboard/")
            self.assertEqual(response.status_code, 200, msg=f"Failed for {username}")
            self.client.logout()

    def test_unauthenticated_dashboard_access_redirects_to_login(self):
        response = self.client.get("/dashboard/")
        self.assertRedirects(response, "/login/?next=/dashboard/", fetch_redirect_response=False)


# ─── Device Form & IP Validation Tests ──────────────────────────────────────────

class DeviceFormTest(TestCase):
    def test_valid_device_form(self):
        form = DeviceForm(data={
            "name": "Test-Router-01",
            "ip_address": "192.168.100.1",
            "device_type": "router",
            "polling_interval": 30,
            "snmp_enabled": False,
            "monitoring_enabled": True,
            "snmp_version": "v2c",
            "snmp_port": 161,
            "snmp_community": "public",
            "snmp_v3_auth_protocol": "SHA",
            "snmp_v3_priv_protocol": "AES",
        })
        self.assertTrue(form.is_valid(), msg=str(form.errors))

    def test_invalid_ip_rejected_by_form(self):
        form = DeviceForm(data={
            "name": "Bad-Device",
            "ip_address": "999.999.999.999",
            "device_type": "router",
            "polling_interval": 30,
            "snmp_enabled": False,
            "monitoring_enabled": True,
            "snmp_version": "v2c",
            "snmp_port": 161,
        })
        self.assertFalse(form.is_valid())
        self.assertIn("ip_address", form.errors)

    def test_duplicate_ip_rejected_by_form(self):
        Device.objects.create(name="Existing-Device", ip_address="10.0.0.50")
        form = DeviceForm(data={
            "name": "New-Device",
            "ip_address": "10.0.0.50",
            "device_type": "switch",
            "polling_interval": 30,
            "snmp_enabled": False,
            "monitoring_enabled": True,
            "snmp_version": "v2c",
            "snmp_port": 161,
        })
        self.assertFalse(form.is_valid())
        self.assertIn("ip_address", form.errors)

    def test_snmpv3_requires_username_and_auth_key(self):
        form = DeviceForm(data={
            "name": "SNMP-Device",
            "ip_address": "10.20.30.1",
            "device_type": "router",
            "polling_interval": 30,
            "monitoring_enabled": True,
            "snmp_enabled": True,
            "snmp_version": "v3",
            "snmp_port": 161,
            "snmp_community": "",
            "snmp_v3_user": "",        # Missing — should fail
            "snmp_v3_auth_key": "",    # Missing — should fail
            "snmp_v3_auth_protocol": "SHA",
            "snmp_v3_priv_protocol": "AES",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("snmp_v3_user", form.errors)

    def test_valid_ipv6_address_accepted(self):
        form = DeviceForm(data={
            "name": "IPv6-Device",
            "ip_address": "2001:db8::1",
            "device_type": "server",
            "polling_interval": 30,
            "snmp_enabled": False,
            "monitoring_enabled": True,
            "snmp_version": "v2c",
            "snmp_port": 161,
        })
        self.assertTrue(form.is_valid(), msg=str(form.errors))


# ─── Device CRUD View Tests ──────────────────────────────────────────────────────

class DeviceCRUDViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.operator = User.objects.create_user(
            username="crud_op", password="CRUDOp99!", email="crud@test.local"
        )
        self.device = Device.objects.create(
            name="Managed-Switch-01",
            ip_address="172.16.10.1",
            device_type=Device.DeviceType.SWITCH,
        )

    def test_device_list_accessible_when_authenticated(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.get("/devices/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Managed-Switch-01")

    def test_device_detail_view(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.get(f"/devices/{self.device.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Managed-Switch-01")
        self.assertContains(response, "172.16.10.1")

    def test_create_device_via_form_view(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.post("/devices/add/", {
            "name": "New-Server-01",
            "ip_address": "10.50.50.1",
            "device_type": "server",
            "polling_interval": 30,
            "monitoring_enabled": "on",
            "snmp_enabled": "",
            "snmp_version": "v2c",
            "snmp_port": 161,
            "snmp_community": "public",
            "snmp_v3_auth_protocol": "SHA",
            "snmp_v3_priv_protocol": "AES",
        })
        self.assertRedirects(response, "/devices/", fetch_redirect_response=False)
        self.assertTrue(Device.objects.filter(name="New-Server-01").exists())

    def test_device_search_filter(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.get("/devices/?q=Managed-Switch")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Managed-Switch-01")

    def test_device_status_filter(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.get("/devices/?status=online")
        self.assertEqual(response.status_code, 200)
        # No online devices yet, table should be empty but page loads fine
        self.assertNotContains(response, "Managed-Switch-01")

    def test_delete_device_view(self):
        self.client.login(username="crud_op", password="CRUDOp99!")
        response = self.client.post(f"/devices/{self.device.pk}/delete/")
        self.assertRedirects(response, "/devices/", fetch_redirect_response=False)
        self.assertFalse(Device.objects.filter(pk=self.device.pk).exists())

    def test_unauthenticated_device_list_redirects(self):
        response = self.client.get("/devices/")
        self.assertRedirects(
            response, "/login/?next=/devices/", fetch_redirect_response=False
        )
