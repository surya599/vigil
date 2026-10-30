from rest_framework import serializers
from .models import Alert, AlertThreshold


class AlertSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    device_ip = serializers.CharField(source="device.ip_address", read_only=True)
    alert_type_display = serializers.CharField(source="get_alert_type_display", read_only=True)
    acknowledged_by_username = serializers.CharField(source="acknowledged_by.username", read_only=True)

    class Meta:
        model = Alert
        fields = (
            "id",
            "device",
            "device_name",
            "device_ip",
            "alert_type",
            "alert_type_display",
            "severity",
            "description",
            "is_acknowledged",
            "acknowledged_by",
            "acknowledged_by_username",
            "acknowledged_at",
            "is_resolved",
            "resolved_at",
            "created_at",
        )
        read_only_fields = (
            "id",
            "created_at",
            "acknowledged_at",
            "resolved_at",
        )


class AlertThresholdSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertThreshold
        fields = "__all__"
