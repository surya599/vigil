from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AlertViewSet, AlertThresholdViewSet

router = DefaultRouter()
router.register(r"alerts", AlertViewSet, basename="alert")
router.register(r"alert-thresholds", AlertThresholdViewSet, basename="alert-threshold")

urlpatterns = [
    path("", include(router.urls)),
]
