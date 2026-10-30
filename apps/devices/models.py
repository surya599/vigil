from django.db import models
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.utils import timezone


mac_validator = RegexValidator(
    regex=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
    message="MAC address must be in format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
)


class Device(models.Model):
    """
    Represents a monitored network asset (Router, Switch, Server, etc.)
    with ICMP availability and SNMP telemetry configuration.
    """

    class DeviceType(models.TextChoices):
        ROUTER = "router", "Router"
        SWITCH = "switch", "Switch"
        SERVER = "server", "Server"
        FIREWALL = "firewall", "Firewall"
        ACCESS_POINT = "access_point", "Access Point"
        WORKSTATION = "workstation", "Workstation"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        ONLINE = "online", "Online"
        OFFLINE = "offline", "Offline"
        WARNING = "warning", "Warning"
        UNKNOWN = "unknown", "Unknown"

    class SNMPVersion(models.TextChoices):
        V2C = "v2c", "SNMPv2c"
        V3 = "v3", "SNMPv3"

    class SNMPAuthProtocol(models.TextChoices):
        SHA = "SHA", "SHA"
        MD5 = "MD5", "MD5"
        NONE = "NONE", "None"

    class SNMPPrivProtocol(models.TextChoices):
        AES = "AES", "AES"
        DES = "DES", "DES"
        NONE = "NONE", "None"

    # Core Identifiers
    name = models.CharField(
        max_length=120,
        unique=True,
        db_index=True,
        help_text="Unique hostname or identifier for the device",
    )
    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=False,
        unique=True,
        db_index=True,
        help_text="Target IPv4 or IPv6 address for ICMP and SNMP polling",
    )
    mac_address = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        validators=[mac_validator],
        help_text="Physical MAC address (e.g. 00:1A:2B:3C:4D:5E)",
    )
    device_type = models.CharField(
        max_length=30,
        choices=DeviceType.choices,
        default=DeviceType.SERVER,
        db_index=True,
        help_text="Categorization of network device",
    )
    location = models.CharField(
        max_length=150,
        blank=True,
        help_text="Physical location (e.g., Data Center Rack A-01, Room 204)",
    )
    description = models.TextField(
        blank=True,
        help_text="Optional remarks, owner, or maintenance notes",
    )

    # State & Operational Tracking
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.UNKNOWN,
        db_index=True,
        help_text="Current operational status",
    )
    monitoring_enabled = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Toggle automated polling for this device",
    )
    polling_interval = models.PositiveIntegerField(
        default=30,
        validators=[MinValueValidator(5), MaxValueValidator(3600)],
        help_text="Polling interval in seconds (default: 30s)",
    )
    consecutive_failures = models.PositiveIntegerField(
        default=0,
        help_text="Count of consecutive ICMP check failures",
    )
    last_checked = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Timestamp of the most recent health check",
    )
    last_status_change = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the device status last transitioned",
    )
    uptime_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=100.00,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Calculated availability percentage (0.00% to 100.00%)",
    )

    # SNMP Telemetry Configuration
    snmp_enabled = models.BooleanField(
        default=False,
        help_text="Enable SNMP telemetry polling (sysDescr, ifTable, etc.)",
    )
    snmp_version = models.CharField(
        max_length=10,
        choices=SNMPVersion.choices,
        default=SNMPVersion.V2C,
        help_text="SNMP protocol version",
    )
    snmp_port = models.PositiveIntegerField(
        default=161,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="SNMP UDP port (default: 161)",
    )
    snmp_community = models.CharField(
        max_length=100,
        blank=True,
        default="public",
        help_text="Community string for SNMPv2c polling",
    )
    snmp_v3_user = models.CharField(
        max_length=100,
        blank=True,
        help_text="SNMPv3 USM username",
    )
    snmp_v3_auth_protocol = models.CharField(
        max_length=10,
        choices=SNMPAuthProtocol.choices,
        default=SNMPAuthProtocol.SHA,
        blank=True,
        help_text="SNMPv3 authentication protocol",
    )
    snmp_v3_auth_key = models.CharField(
        max_length=128,
        blank=True,
        help_text="SNMPv3 authentication passphrase",
    )
    snmp_v3_priv_protocol = models.CharField(
        max_length=10,
        choices=SNMPPrivProtocol.choices,
        default=SNMPPrivProtocol.AES,
        blank=True,
        help_text="SNMPv3 privacy / encryption protocol",
    )
    snmp_v3_priv_key = models.CharField(
        max_length=128,
        blank=True,
        help_text="SNMPv3 privacy passphrase",
    )

    # SNMP Cache / Cached System Metadata
    sys_description = models.TextField(
        blank=True,
        help_text="System description string fetched via SNMP (OID 1.3.6.1.2.1.1.1.0)",
    )
    sys_uptime = models.CharField(
        max_length=100,
        blank=True,
        help_text="System uptime fetched via SNMP (OID 1.3.6.1.2.1.1.3.0)",
    )

    # Audit Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Network Device"
        verbose_name_plural = "Network Devices"
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["ip_address", "status"]),
            models.Index(fields=["device_type", "status"]),
            models.Index(fields=["monitoring_enabled", "last_checked"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.ip_address}) - {self.get_status_display()}"

    @property
    def is_online(self) -> bool:
        return self.status == self.Status.ONLINE

    @property
    def is_offline(self) -> bool:
        return self.status == self.Status.OFFLINE

    @property
    def is_warning(self) -> bool:
        return self.status == self.Status.WARNING

    @property
    def latest_metric(self):
        """Returns the most recently recorded DeviceMetric or None."""
        return self.metrics.order_by("-recorded_at").first()

    def update_status(self, new_status: str):
        """Records status change timestamp if transitioning."""
        if self.status != new_status:
            self.status = new_status
            self.last_status_change = timezone.now()
        self.last_checked = timezone.now()
        self.save(update_fields=["status", "last_status_change", "last_checked", "consecutive_failures"])
