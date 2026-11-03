from rest_framework import serializers
from .models import Device, DiscoveredDevice, DiscoveryScan, NetworkChangeEvent


class DeviceSerializer(serializers.ModelSerializer):
    """
    Serializer for network device management.
    Secures SNMP secrets by setting write_only=True on sensitive credentials.
    """

    status_display = serializers.CharField(source="get_status_display", read_only=True)
    device_type_display = serializers.CharField(source="get_device_type_display", read_only=True)

    # Sensitive SNMP credentials protected from GET exposure
    snmp_community = serializers.CharField(write_only=True, required=False, allow_blank=True)
    snmp_v3_auth_key = serializers.CharField(write_only=True, required=False, allow_blank=True)
    snmp_v3_priv_key = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Device
        fields = (
            "id",
            "name",
            "ip_address",
            "mac_address",
            "hostname",
            "manufacturer",
            "device_type",
            "device_type_display",
            "location",
            "description",
            "status",
            "status_display",
            "monitoring_enabled",
            "polling_interval",
            "consecutive_failures",
            "last_checked",
            "last_status_change",
            "uptime_percentage",
            "cpu_utilization",
            "memory_utilization",
            "snmp_enabled",
            "snmp_version",
            "snmp_port",
            "snmp_community",
            "snmp_v3_user",
            "snmp_v3_auth_protocol",
            "snmp_v3_auth_key",
            "snmp_v3_priv_protocol",
            "snmp_v3_priv_key",
            "sys_object_id",
            "sys_description",
            "sys_uptime",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "consecutive_failures",
            "last_checked",
            "last_status_change",
            "uptime_percentage",
            "created_at",
            "updated_at",
        )


class DiscoveryScanSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    started_by_username = serializers.CharField(source="started_by.username", read_only=True, default="system")

    class Meta:
        model = DiscoveryScan
        fields = (
            "id",
            "interface_name",
            "target_cidr",
            "status",
            "status_display",
            "progress_pct",
            "total_hosts_scanned",
            "discovered_count",
            "new_devices_count",
            "changes_detected_count",
            "scan_methods",
            "started_by_username",
            "started_at",
            "completed_at",
            "duration_seconds",
            "error_message",
        )


class DiscoveredDeviceSerializer(serializers.ModelSerializer):
    device_type_display = serializers.CharField(source="get_device_type_display", read_only=True)
    trust_status_display = serializers.CharField(source="get_trust_status_display", read_only=True)
    confidence_label = serializers.CharField(read_only=True)
    is_monitored = serializers.BooleanField(read_only=True)

    class Meta:
        model = DiscoveredDevice
        fields = (
            "id",
            "ip_address",
            "mac_address",
            "hostname",
            "manufacturer",
            "device_type",
            "device_type_display",
            "type_manually_set",
            "confidence_score",
            "confidence_label",
            "classification_reason",
            "discovery_methods",
            "is_reachable",
            "latency_ms",
            "open_ports",
            "sys_description",
            "sys_object_id",
            "subnet_cidr",
            "interface_name",
            "trust_status",
            "trust_status_display",
            "is_monitored",
            "monitored_device",
            "first_discovered_at",
            "last_discovered_at",
        )


class NetworkChangeEventSerializer(serializers.ModelSerializer):
    event_type_display = serializers.CharField(source="get_event_type_display", read_only=True)
    severity_display = serializers.CharField(source="get_severity_display", read_only=True)
    ip_address = serializers.CharField(source="discovered_device.ip_address", read_only=True, default="")
    hostname = serializers.CharField(source="discovered_device.hostname", read_only=True, default="")

    class Meta:
        model = NetworkChangeEvent
        fields = (
            "id",
            "discovered_device",
            "ip_address",
            "hostname",
            "event_type",
            "event_type_display",
            "severity",
            "severity_display",
            "previous_value",
            "new_value",
            "description",
            "is_acknowledged",
            "created_at",
        )
