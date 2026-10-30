from django.contrib import admin
from .models import Alert, AlertThreshold


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "device",
        "alert_type",
        "severity",
        "is_acknowledged",
        "acknowledged_by",
        "is_resolved",
        "created_at",
    )
    list_filter = ("severity", "alert_type", "is_acknowledged", "is_resolved", "created_at")
    search_fields = ("device__name", "description")
    readonly_fields = ("created_at", "acknowledged_at", "resolved_at")
    actions = ["acknowledge_alerts", "resolve_alerts"]

    @admin.action(description="Acknowledge selected alerts")
    def acknowledge_alerts(self, request, queryset):
        for alert in queryset.filter(is_acknowledged=False):
            alert.acknowledge(request.user)

    @admin.action(description="Resolve selected alerts")
    def resolve_alerts(self, request, queryset):
        for alert in queryset.filter(is_resolved=False):
            alert.resolve()


@admin.register(AlertThreshold)
class AlertThresholdAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "high_latency_warning_ms",
        "high_latency_critical_ms",
        "packet_loss_warning_pct",
        "packet_loss_critical_pct",
        "consecutive_failures_for_offline",
        "is_active",
    )
    list_filter = ("is_active",)
