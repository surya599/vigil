from rest_framework import serializers
from .models import NetworkTrafficSnapshot, DeviceDailySummary


class NetworkTrafficSnapshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkTrafficSnapshot
        fields = "__all__"


class DeviceDailySummarySerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)

    class Meta:
        model = DeviceDailySummary
        fields = "__all__"
