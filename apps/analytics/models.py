from django.db import models
from django.utils import timezone


class NetworkTrafficSnapshot(models.Model):
    """
    Periodic network-wide aggregate metrics stored for high-performance NOC dashboard
    graphs and historical trend analysis without heavy on-the-fly table scans.
    """

    recorded_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="Snapshot timestamp",
    )
    total_devices = models.PositiveIntegerField(default=0)
    online_devices = models.PositiveIntegerField(default=0)
    offline_devices = models.PositiveIntegerField(default=0)
    warning_devices = models.PositiveIntegerField(default=0)

    average_latency = models.FloatField(
        default=0.0,
        help_text="Network-wide average latency in ms",
    )
    average_packet_loss = models.FloatField(
        default=0.0,
        help_text="Network-wide average packet loss percentage",
    )
    total_incoming_bps = models.FloatField(
        default=0.0,
        help_text="Aggregate incoming traffic rate across all interfaces (bits/s)",
    )
    total_outgoing_bps = models.FloatField(
        default=0.0,
        help_text="Aggregate outgoing traffic rate across all interfaces (bits/s)",
    )

    class Meta:
        verbose_name = "Network Traffic Snapshot"
        verbose_name_plural = "Network Traffic Snapshots"
        ordering = ["-recorded_at"]
        indexes = [
            models.Index(fields=["-recorded_at"]),
        ]

    def __str__(self):
        return f"Snapshot at {self.recorded_at:%Y-%m-%d %H:%M} - {self.online_devices}/{self.total_devices} Online"


class DeviceDailySummary(models.Model):
    """
    Day-level rollup summary for each device computing uptime, outages, and SLA.
    """

    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="daily_summaries",
        db_index=True,
    )
    date = models.DateField(db_index=True)
    uptime_seconds = models.PositiveIntegerField(default=86400)
    downtime_seconds = models.PositiveIntegerField(default=0)
    uptime_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=100.00,
    )
    avg_latency = models.FloatField(default=0.0)
    max_latency = models.FloatField(default=0.0)
    avg_packet_loss = models.FloatField(default=0.0)
    total_alerts_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Device Daily Summary"
        verbose_name_plural = "Device Daily Summaries"
        ordering = ["-date", "device"]
        unique_together = [("device", "date")]
        indexes = [
            models.Index(fields=["device", "-date"]),
        ]

    def __str__(self):
        return f"{self.device.name} Summary for {self.date} (Uptime: {self.uptime_percentage}%)"
