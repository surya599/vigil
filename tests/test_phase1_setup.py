import pytest
from django.db import connection
from django.conf import settings
from django.test import Client


@pytest.mark.django_db
def test_postgresql_connection():
    """Verify that Django can successfully connect to PostgreSQL and execute queries."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 + 1;")
        row = cursor.fetchone()
        assert row[0] == 2

    assert "postgresql" in settings.DATABASES["default"]["ENGINE"]
    assert "netpulse_db" in settings.DATABASES["default"]["NAME"]


def test_project_configuration():
    """Verify critical project settings are properly loaded from environment."""
    assert settings.ROOT_URLCONF == "config.urls"
    assert "rest_framework" in settings.INSTALLED_APPS
    assert settings.TIME_ZONE == "Asia/Kolkata"
    assert settings.USE_TZ is True


@pytest.mark.django_db
def test_health_check_endpoint():
    """Verify that the health check endpoint returns 200 and healthy database status."""
    client = Client()
    response = client.get("/api/health/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["platform"] == "VIGIL"
    assert data["service"] == "VIGIL Network Intelligence Platform"
    assert data["database"] == "healthy"
