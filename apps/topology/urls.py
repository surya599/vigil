from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TopologyView, NetworkConnectionViewSet

app_name = "topology"

router = DefaultRouter()
router.register(r"connections", NetworkConnectionViewSet, basename="connection-api")

urlpatterns = [
    # UI View
    path("topology/", TopologyView.as_view(), name="topology-view"),

    # REST APIs (matching /api/topology/connections/)
    path("api/topology/", include(router.urls)),
]
