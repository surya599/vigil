from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import (
    NetworkConnectionViewSet,
    TopologyView,
    topology_discover_api,
    topology_graph_api,
)

app_name = "topology"

router = DefaultRouter()
router.register(r"connections", NetworkConnectionViewSet, basename="connection-api")

urlpatterns = [
    # UI View
    path("topology/", TopologyView.as_view(), name="topology-view"),

    # REST APIs for interactive graph, auto-discovery, and link CRUD
    path("api/topology/graph/", topology_graph_api, name="topology-graph-api"),
    path("api/topology/discover/", topology_discover_api, name="topology-discover-api"),
    path("api/topology/", include(router.urls)),
]
