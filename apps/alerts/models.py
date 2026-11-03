from django.db import models
from django.conf import settings
from django.utils import timezone


class Alert(models.Model):
    """
    Represents an incident or abnormal operational event on a monitored asset.
    """

    class AlertType(models.TextChoices):
        DEVICE_OFFLINE = "device_offline", "Device Offline"
        DEVICE_RECOVERED = "device_recovered", "Device Recovered"
        HIGH_LATENCY = "high_latency", "High Latency Warning"
        PACKET_LOSS = "packet_loss", "Packet Loss Alert"
        HIGH_CPU = "high_cpu", "High CPU Utilization"
        HIGH_MEMORY = "high_memory", "High Memory Utilization"
        INTERFACE_DOWN = "interface_down", "Network Interface Down"
        SNMP_FAILURE = "snmp_failure", "SNMP Collection Failure"
        THRESHOLD_EXCEEDED = "threshold_exceeded", "Bandwidth Threshold Exceeded"
        NEW_DEVICE_DISCOVERED = "new_device_discovered", "Newly Discovered Device"
        UNKNOWN_DEVICE_DETECTED = "unknown_device_detected", "Unknown Device Detected"
        NETWORK_CHANGE = "network_change", "Network Inventory Change"

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"  # Red
        WARNING = "warning", "Warning"    # Amber
        INFO = "info", "Informational"    # Blue

    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="alerts",
        db_index=True,
    )
    alert_type = models.CharField(
        max_length=40,
        choices=AlertType.choices,
        db_index=True,
    )
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.WARNING,
        db_index=True,
    )
    description = models.TextField(
        help_text="Human-readable incident summary detailing the trigger condition",
    )

    # Acknowledgement State
    is_acknowledged = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether a NOC operator has acknowledged this incident",
    )
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acknowledged_alerts",
        help_text="Operator who acknowledged the incident",
    )
    acknowledged_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when acknowledgement occurred",
    )

    # Resolution State
    is_resolved = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether this condition has cleared or recovered",
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when incident condition normalized",
    )

    created_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="Timestamp when alert was triggered",
    )

    class Meta:
        verbose_name = "Alert"
        verbose_name_plural = "Alerts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["device", "is_resolved", "severity"]),
            models.Index(fields=["is_acknowledged", "is_resolved"]),
            models.Index(fields=["alert_type", "is_resolved"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.device.name} - {self.get_alert_type_display()} ({'Resolved' if self.is_resolved else 'Active'})"

    def acknowledge(self, user):
        """Marks the alert as acknowledged by a specified user and broadcasts to NOC."""
        self.is_acknowledged = True
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.save(update_fields=["is_acknowledged", "acknowledged_by", "acknowledged_at"])
        from monitoring.broadcaster import broadcast_alert_event
        broadcast_alert_event(self, event="acknowledged")

    def resolve(self):
        """Marks the alert as resolved when device or interface metrics return to normal."""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.save(update_fields=["is_resolved", "resolved_at"])
        from monitoring.broadcaster import broadcast_alert_event
        broadcast_alert_event(self, event="resolved")


class AlertThreshold(models.Model):
    """
    Configurable monitoring thresholds used by the alerting engine.
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        default="Default Global Thresholds",
    )
    high_latency_warning_ms = models.FloatField(
        default=100.0,
        help_text="Latency threshold in ms triggering a Warning alert",
    )
    high_latency_critical_ms = models.FloatField(
        default=300.0,
        help_text="Latency threshold in ms triggering a Critical alert",
    )
    packet_loss_warning_pct = models.FloatField(
        default=5.0,
        help_text="Packet loss percentage triggering a Warning alert",
    )
    packet_loss_critical_pct = models.FloatField(
        default=25.0,
        help_text="Packet loss percentage triggering a Critical alert",
    )
    consecutive_failures_for_offline = models.PositiveIntegerField(
        default=3,
        help_text="Number of consecutive ICMP check failures before marking device Offline",
    )
    cpu_warning_pct = models.FloatField(
        default=80.0,
        help_text="CPU utilization percentage triggering a Warning alert",
    )
    cpu_critical_pct = models.FloatField(
        default=95.0,
        help_text="CPU utilization percentage triggering a Critical alert",
    )
    memory_warning_pct = models.FloatField(
        default=85.0,
        help_text="Memory utilization percentage triggering a Warning alert",
    )
    memory_critical_pct = models.FloatField(
        default=95.0,
        help_text="Memory utilization percentage triggering a Critical alert",
    )
    bandwidth_warning_pct = models.FloatField(
        default=80.0,
        help_text="Interface bandwidth utilization percentage triggering an alert",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this threshold profile is currently in effect",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Alert Threshold"
        verbose_name_plural = "Alert Thresholds"

    def __str__(self):
        return f"{self.name} ({'Active' if self.is_active else 'Inactive'})"
