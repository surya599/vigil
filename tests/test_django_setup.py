from django.test import TestCase, Client
from django.db import connection
from django.conf import settings


class SetupVerificationTest(TestCase):
    def test_database_connection(self):
        """Verify that Django TestCase can execute queries against PostgreSQL."""
        with connection.cursor() as cursor:
            cursor.execute("SELECT 2 + 3;")
            result = cursor.fetchone()
            self.assertEqual(result[0], 5)

    def test_health_check_api(self):
        """Verify the health check endpoint returns 200 and healthy database status."""
        client = Client()
        response = client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["database"], "healthy")
