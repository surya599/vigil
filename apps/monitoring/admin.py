from django.contrib import admin
from .models import DeviceMetric, NetworkInterface, InterfaceMetric


@admin.register(DeviceMetric)
class DeviceMetricAdmin(admin.ModelAdmin):
    list_display = ("device", "status", "latency", "packet_loss", "jitter", "recorded_at")
    list_filter = ("status", "recorded_at", "device")
    search_fields = ("device__name", "device__ip_address")
    readonly_fields = ("device", "status", "latency", "packet_loss", "jitter", "recorded_at")

    def has_add_permission(self, request):
        return False


class InterfaceMetricInline(admin.TabularInline):
    model = InterfaceMetric
    extra = 0
    readonly_fields = ("incoming_bytes", "outgoing_bytes", "incoming_bps", "outgoing_bps", "recorded_at")
    can_delete = False
    max_num = 10


@admin.register(NetworkInterface)
class NetworkInterfaceAdmin(admin.ModelAdmin):
    list_display = (
        "device",
        "interface_name",
        "interface_index",
        "operational_status",
        "admin_status",
        "speed_bps",
        "last_updated",
    )
    list_filter = ("operational_status", "admin_status", "device")
    search_fields = ("device__name", "interface_name", "mac_address", "ip_address")
    inlines = [InterfaceMetricInline]


@admin.register(InterfaceMetric)
class InterfaceMetricAdmin(admin.ModelAdmin):
    list_display = ("interface", "incoming_bps", "outgoing_bps", "incoming_bytes", "outgoing_bytes", "recorded_at")
    list_filter = ("recorded_at", "interface__device")
    search_fields = ("interface__interface_name", "interface__device__name")
    readonly_fields = ("interface", "incoming_bytes", "outgoing_bytes", "incoming_bps", "outgoing_bps", "recorded_at")

    def has_add_permission(self, request):
        return False
