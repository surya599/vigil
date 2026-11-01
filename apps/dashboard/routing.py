"""
WebSocket URL routing for the NetPulse NOC dashboard and device detail views.
"""

from django.urls import path

from .consumers import DeviceDetailConsumer, NOCDashboardConsumer

websocket_urlpatterns = [
    path("ws/noc/", NOCDashboardConsumer.as_asgi(), name="ws-noc-dashboard"),
    path("ws/devices/<int:device_id>/", DeviceDetailConsumer.as_asgi(), name="ws-device-detail"),
]
