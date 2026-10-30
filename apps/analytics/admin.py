from django.contrib import admin
from .models import NetworkTrafficSnapshot, DeviceDailySummary


@admin.register(NetworkTrafficSnapshot)
class NetworkTrafficSnapshotAdmin(admin.ModelAdmin):
    list_display = (
        "recorded_at",
        "total_devices",
        "online_devices",
        "offline_devices",
        "average_latency",
        "average_packet_loss",
        "total_incoming_bps",
        "total_outgoing_bps",
    )
    list_filter = ("recorded_at",)
    readonly_fields = [f.name for f in NetworkTrafficSnapshot._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(DeviceDailySummary)
class DeviceDailySummaryAdmin(admin.ModelAdmin):
    list_display = (
        "device",
        "date",
        "uptime_percentage",
        "avg_latency",
        "max_latency",
        "avg_packet_loss",
        "total_alerts_count",
    )
    list_filter = ("date", "device")
    search_fields = ("device__name",)
