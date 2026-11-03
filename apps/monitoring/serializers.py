from rest_framework import serializers
from .models import DeviceMetric, NetworkInterface, InterfaceMetric


class DeviceMetricSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    device_ip = serializers.CharField(source="device.ip_address", read_only=True)

    class Meta:
        model = DeviceMetric
        fields = (
            "id",
            "device",
            "device_name",
            "device_ip",
            "status",
            "latency",
            "packet_loss",
            "jitter",
            "cpu_utilization",
            "memory_utilization",
            "recorded_at",
        )


class InterfaceMetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = InterfaceMetric
        fields = (
            "id",
            "interface",
            "incoming_bytes",
            "outgoing_bytes",
            "incoming_bps",
            "outgoing_bps",
            "in_errors",
            "out_errors",
            "in_discards",
            "out_discards",
            "recorded_at",
        )


class NetworkInterfaceSerializer(serializers.ModelSerializer):
    latest_metric = InterfaceMetricSerializer(read_only=True)

    class Meta:
        model = NetworkInterface
        fields = (
            "id",
            "device",
            "interface_name",
            "interface_index",
            "mac_address",
            "ip_address",
            "speed_bps",
            "operational_status",
            "admin_status",
            "description",
            "last_updated",
            "latest_metric",
        )
