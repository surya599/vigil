from rest_framework import serializers
from .models import NetworkConnection


class NetworkConnectionSerializer(serializers.ModelSerializer):
    source_device_name = serializers.CharField(source="source_device.name", read_only=True)
    source_device_ip = serializers.CharField(source="source_device.ip_address", read_only=True)
    source_device_type = serializers.CharField(source="source_device.device_type", read_only=True)
    source_device_status = serializers.CharField(source="source_device.status", read_only=True)

    destination_device_name = serializers.CharField(source="destination_device.name", read_only=True)
    destination_device_ip = serializers.CharField(source="destination_device.ip_address", read_only=True)
    destination_device_type = serializers.CharField(source="destination_device.device_type", read_only=True)
    destination_device_status = serializers.CharField(source="destination_device.status", read_only=True)

    connection_type_display = serializers.CharField(source="get_connection_type_display", read_only=True)

    class Meta:
        model = NetworkConnection
        fields = (
            "id",
            "source_device",
            "source_device_name",
            "source_device_ip",
            "source_device_type",
            "source_device_status",
            "destination_device",
            "destination_device_name",
            "destination_device_ip",
            "destination_device_type",
            "destination_device_status",
            "connection_type",
            "connection_type_display",
            "source_interface",
            "destination_interface",
            "link_speed",
            "status",
            "is_discovered",
            "description",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def validate(self, attrs):
        src = attrs.get("source_device") or getattr(self.instance, "source_device", None)
        dst = attrs.get("destination_device") or getattr(self.instance, "destination_device", None)
        if src and dst and src.id == dst.id:
            raise serializers.ValidationError(
                "A device cannot connect directly to itself in topology."
            )
        return attrs
