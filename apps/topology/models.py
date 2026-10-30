from django.db import models
from django.core.exceptions import ValidationError


class NetworkConnection(models.Model):
    """
    Represents a link (physical cable, fiber trunk, wireless bridge, or logical tunnel)
    between two registered network devices in the topology graph.
    """

    class ConnectionType(models.TextChoices):
        ETHERNET = "ethernet", "Ethernet (Copper)"
        FIBER = "fiber", "Fiber Optic"
        WIRELESS = "wireless", "Wireless Link"
        WAN = "wan", "WAN / MPLS"
        LOGICAL = "logical", "Logical / Trunk / VPN"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active (Up)"
        DEGRADED = "degraded", "Degraded"
        DOWN = "down", "Down"

    source_device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="outgoing_connections",
        help_text="Originating device node in topology",
    )
    destination_device = models.ForeignKey(
        "devices.Device",
        on_delete=models.CASCADE,
        related_name="incoming_connections",
        help_text="Target device node in topology",
    )
    connection_type = models.CharField(
        max_length=30,
        choices=ConnectionType.choices,
        default=ConnectionType.ETHERNET,
        help_text="Physical or logical medium",
    )
    source_interface = models.ForeignKey(
        "monitoring.NetworkInterface",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="source_connections",
        help_text="Specific source interface port",
    )
    destination_interface = models.ForeignKey(
        "monitoring.NetworkInterface",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="destination_connections",
        help_text="Specific destination interface port",
    )
    link_speed = models.CharField(
        max_length=50,
        default="1 Gbps",
        blank=True,
        help_text="Rated link speed (e.g., 100 Mbps, 1 Gbps, 10 Gbps)",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        help_text="Operational status of the link",
    )
    is_discovered = models.BooleanField(
        default=False,
        help_text="True if automatically discovered via LLDP/CDP/ARP; False if configured manually by administrator",
    )
    description = models.TextField(
        blank=True,
        help_text="Notes on link path, patch panel, VLAN tag, etc.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Network Connection"
        verbose_name_plural = "Network Connections"
        ordering = ["source_device", "destination_device"]
        unique_together = [("source_device", "destination_device")]
        indexes = [
            models.Index(fields=["source_device", "destination_device"]),
            models.Index(fields=["status"]),
            models.Index(fields=["is_discovered"]),
        ]

    def clean(self):
        super().clean()
        if self.source_device_id and self.destination_device_id:
            if self.source_device_id == self.destination_device_id:
                raise ValidationError("A device cannot connect directly to itself in topology.")

    def __str__(self):
        discovery_tag = " [Discovered]" if self.is_discovered else " [Manual]"
        return f"{self.source_device.name} -> {self.destination_device.name} ({self.get_connection_type_display()}){discovery_tag}"
