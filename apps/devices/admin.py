from django.contrib import admin
from .models import Device


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "ip_address",
        "device_type",
        "status",
        "monitoring_enabled",
        "polling_interval",
        "consecutive_failures",
        "last_checked",
    )
    list_filter = (
        "status",
        "device_type",
        "monitoring_enabled",
        "snmp_enabled",
        "snmp_version",
    )
    search_fields = ("name", "ip_address", "mac_address", "location")
    readonly_fields = (
        "last_checked",
        "last_status_change",
        "consecutive_failures",
        "created_at",
        "updated_at",
    )
    fieldsets = (
        (
            "Identification",
            {
                "fields": (
                    "name",
                    "ip_address",
                    "mac_address",
                    "device_type",
                    "location",
                    "description",
                )
            },
        ),
        (
            "Operational Status & Monitoring",
            {
                "fields": (
                    "status",
                    "monitoring_enabled",
                    "polling_interval",
                    "consecutive_failures",
                    "uptime_percentage",
                    "last_checked",
                    "last_status_change",
                )
            },
        ),
        (
            "SNMP Telemetry Configuration",
            {
                "classes": ("collapse",),
                "fields": (
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
                ),
            },
        ),
        (
            "Audit Metadata",
            {
                "classes": ("collapse",),
                "fields": ("created_at", "updated_at"),
            },
        ),
    )
