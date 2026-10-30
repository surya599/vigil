from rest_framework import serializers
from .models import Device


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
            "snmp_enabled",
            "snmp_version",
            "snmp_port",
            "snmp_community",
            "snmp_v3_user",
            "snmp_v3_auth_protocol",
            "snmp_v3_auth_key",
            "snmp_v3_priv_protocol",
            "snmp_v3_priv_key",
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
