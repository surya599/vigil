"""
VIGIL Phase 1 Automated Tests:
Verifies complete visual and metadata rebranding to VIGIL (Network Intelligence Platform –
"See Everything. Miss Nothing.") across login, sidebar, dashboard, footer, page titles,
SVG logo/favicon assets, health API, and backward compatibility of internal identifiers.
"""
from pathlib import Path
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.forms import VigilLoginForm, NetPulseLoginForm

User = get_user_model()


class VigilBrandingAndIdentityTest(TestCase):
    """Verify VIGIL branding across templates, metadata, static assets, and APIs."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="vigil_admin",
            email="admin@vigil.local",
            password="VigilPassword!2026",
        )
        self.user.profile.role = "admin"
        self.user.profile.save()

    def test_login_page_displays_vigil_brand_identity(self):
        res = self.client.get(reverse("accounts:login"))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "VIGIL")
        self.assertContains(res, "Network Intelligence Platform")
        self.assertContains(res, "See Everything. Miss Nothing.")
        self.assertContains(res, "Sign In to VIGIL")
        self.assertContains(res, "Intelligent Network Discovery, Monitoring and Analytics")
        self.assertContains(res, "images/favicon.svg")

    def test_sidebar_topbar_footer_and_metadata_across_authenticated_views(self):
        self.client.force_login(self.user)
        routes = [
            reverse("dashboard:overview"),
            reverse("devices:device-list"),
            reverse("topology:topology-view"),
            reverse("analytics:traffic-analytics"),
            reverse("monitoring:performance"),
            reverse("monitoring:history"),
            reverse("alerts:alert-list"),
            reverse("alerts:settings"),
            reverse("accounts:profile"),
            reverse("accounts:user-list"),
        ]
        for url in routes:
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, f"Failed rendering {url}")
            self.assertContains(res, "<title>", msg_prefix=f"Missing <title> on {url}")
            self.assertContains(res, "VIGIL", msg_prefix=f"Missing VIGIL brand on {url}")
            self.assertContains(res, "Network Intelligence Platform")
            self.assertContains(res, "See Everything. Miss Nothing.")
            self.assertContains(res, 'id="vigil-footer"')
            self.assertContains(res, 'name="application-name" content="VIGIL"')
            self.assertContains(res, "images/favicon.svg")

    def test_vigil_svg_logo_and_favicon_assets_exist(self):
        static_dir = Path(settings.BASE_DIR) / "static" / "images"
        logo_path = static_dir / "vigil-logo.svg"
        favicon_path = static_dir / "favicon.svg"

        self.assertTrue(logo_path.exists(), "static/images/vigil-logo.svg must exist")
        self.assertTrue(favicon_path.exists(), "static/images/favicon.svg must exist")

        logo_content = logo_path.read_text(encoding="utf-8")
        favicon_content = favicon_path.read_text(encoding="utf-8")
        self.assertIn("<svg", logo_content)
        self.assertIn("<svg", favicon_content)

    def test_health_endpoint_returns_vigil_platform_metadata(self):
        res = self.client.get(reverse("system-health"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["platform"], "VIGIL")
        self.assertEqual(data["category"], "Network Intelligence Platform")
        self.assertEqual(data["tagline"], "See Everything. Miss Nothing.")
        self.assertEqual(
            data["description"],
            "Intelligent Network Discovery, Monitoring and Analytics.",
        )
        self.assertEqual(data["status"], "online")

    def test_backward_compatible_app_names_and_form_aliases(self):
        self.assertIs(VigilLoginForm, NetPulseLoginForm)
        expected_apps = {
            "accounts",
            "devices",
            "monitoring",
            "analytics",
            "alerts",
            "topology",
            "dashboard",
        }
        self.assertTrue(expected_apps.issubset(set(settings.INSTALLED_APPS)))
