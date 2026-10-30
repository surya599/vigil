from django.db import models
from django.utils import timezone


class DeviceMetric(models.Model):
    """
    Time-series metric entry capturing device availability,
    round-trip ICMP latency, packet loss, and jitter.
    """

    class Status(models.TextChoices):
        ONLINE = "online", "Online"
        OFFLINE = "offline", "Offline"
        WARNING = "warning", "Warning"

    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="metrics",
        db_index=True,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        db_index=True,
    )
    latency = models.FloatField(
        null=True,
        blank=True,
        help_text="Round-trip latency in milliseconds (ms)",
    )
    packet_loss = models.FloatField(
        default=0.0,
        help_text="Measured packet loss percentage (0.0 to 100.0)",
    )
    jitter = models.FloatField(
        null=True,
        blank=True,
        help_text="Calculated latency jitter in milliseconds (ms)",
    )
    recorded_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="Timestamp when metric was polled",
    )

    class Meta:
        verbose_name = "Device Metric"
        verbose_name_plural = "Device Metrics"
        ordering = ["-recorded_at"]
        indexes = [
            models.Index(fields=["device", "-recorded_at"]),
            models.Index(fields=["device", "status"]),
            models.Index(fields=["recorded_at"]),
        ]

    def __str__(self):
        return f"{self.device.name} - {self.status} ({self.latency or 0:.1f}ms) at {self.recorded_at:%Y-%m-%d %H:%M:%S}"


class NetworkInterface(models.Model):
    """
    Represents a physical or virtual network interface on a monitored device
    (e.g., eth0, GigabitEthernet0/1, wlan0).
    """

    class OperationalStatus(models.TextChoices):
        UP = "up", "Up"
        DOWN = "down", "Down"
        TESTING = "testing", "Testing"
        UNKNOWN = "unknown", "Unknown"

    class AdminStatus(models.TextChoices):
        UP = "up", "Up"
        DOWN = "down", "Down"
        UNKNOWN = "unknown", "Unknown"

    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="interfaces",
        db_index=True,
    )
    interface_name = models.CharField(
        max_length=100,
        help_text="Interface identifier (e.g., eth0, GigabitEthernet0/0/1)",
    )
    interface_index = models.IntegerField(
        default=0,
        help_text="SNMP MIB-II ifIndex",
    )
    mac_address = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        help_text="Hardware address for this interface",
    )
    ip_address = models.GenericIPAddressField(
        protocol="both",
        null=True,
        blank=True,
        help_text="Configured IP address on this interface",
    )
    speed_bps = models.BigIntegerField(
        default=0,
        help_text="Interface capacity in bits per second (e.g. 1000000000 for 1Gbps)",
    )
    operational_status = models.CharField(
        max_length=20,
        choices=OperationalStatus.choices,
        default=OperationalStatus.UNKNOWN,
        db_index=True,
    )
    admin_status = models.CharField(
        max_length=20,
        choices=AdminStatus.choices,
        default=AdminStatus.UP,
    )
    description = models.TextField(
        blank=True,
        help_text="Interface alias / SNMP ifAlias or ifDescr",
    )
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Network Interface"
        verbose_name_plural = "Network Interfaces"
        ordering = ["device", "interface_index", "interface_name"]
        unique_together = [("device", "interface_name")]
        indexes = [
            models.Index(fields=["device", "operational_status"]),
        ]

    def __str__(self):
        return f"{self.device.name} - {self.interface_name} ({self.operational_status})"

    @property
    def is_up(self) -> bool:
        return self.operational_status == self.OperationalStatus.UP

    @property
    def latest_metric(self):
        """Returns the most recent bandwidth metric for this interface."""
        return self.metrics.order_by("-recorded_at").first()


class InterfaceMetric(models.Model):
    """
    Time-series bandwidth statistics recording raw octet counters and calculated bps.
    """

    interface = models.ForeignKey(
        NetworkInterface,
        on_delete=models.CASCADE,
        related_name="metrics",
        db_index=True,
    )
    incoming_bytes = models.BigIntegerField(
        default=0,
        help_text="Raw cumulative SNMP ifInOctets / ifHCInOctets counter",
    )
    outgoing_bytes = models.BigIntegerField(
        default=0,
        help_text="Raw cumulative SNMP ifOutOctets / ifHCOutOctets counter",
    )
    incoming_bps = models.FloatField(
        default=0.0,
        help_text="Calculated incoming traffic rate in bits per second",
    )
    outgoing_bps = models.FloatField(
        default=0.0,
        help_text="Calculated outgoing traffic rate in bits per second",
    )
    recorded_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="Measurement timestamp",
    )

    class Meta:
        verbose_name = "Interface Metric"
        verbose_name_plural = "Interface Metrics"
        ordering = ["-recorded_at"]
        indexes = [
            models.Index(fields=["interface", "-recorded_at"]),
            models.Index(fields=["recorded_at"]),
        ]

    def __str__(self):
        return (
            f"{self.interface.interface_name} "
            f"[In: {self.incoming_bps/1_000_000:.2f} Mbps, "
            f"Out: {self.outgoing_bps/1_000_000:.2f} Mbps] "
            f"at {self.recorded_at:%H:%M:%S}"
        )
