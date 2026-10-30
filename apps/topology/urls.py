from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import NetworkConnectionViewSet

router = DefaultRouter()
router.register(r"connections", NetworkConnectionViewSet, basename="network-connection")

urlpatterns = [
    path("", include(router.urls)),
]
