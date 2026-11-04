from typing import Optional
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
        ACCESS_POINT = "access_point", "Wireless Access Point"
        LAPTOP = "laptop", "Laptop"
        DESKTOP = "desktop", "Desktop"
        SMARTPHONE = "smartphone", "Smartphone"
        TABLET = "tablet", "Tablet"
        PRINTER = "printer", "Printer"
        SERVER = "server", "Server"
        IOT = "iot", "IoT Device"
        FIREWALL = "firewall", "Firewall"
        APPLIANCE = "appliance", "Network Appliance"
        WORKSTATION = "workstation", "Workstation"
        MOBILE = "mobile", "Mobile Phone"
        UNKNOWN = "unknown", "Unknown Device"
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

    # SNMP Cache / Cached System Metadata & Resource Telemetry
    hostname = models.CharField(
        max_length=150,
        blank=True,
        help_text="Resolved DNS or SNMP sysName hostname",
    )
    manufacturer = models.CharField(
        max_length=120,
        blank=True,
        help_text="Hardware vendor identified via IEEE MAC OUI or SNMP",
    )
    sys_object_id = models.CharField(
        max_length=150,
        blank=True,
        help_text="SNMP sysObjectID (OID 1.3.6.1.2.1.1.2.0)",
    )
    sys_description = models.TextField(
        blank=True,
        help_text="System description string fetched via SNMP (OID 1.3.6.1.2.1.1.1.0)",
    )
    sys_uptime = models.CharField(
        max_length=100,
        blank=True,
        help_text="System uptime fetched via SNMP (OID 1.3.6.1.2.1.1.3.0)",
    )
    cpu_utilization = models.FloatField(
        null=True,
        blank=True,
        help_text="Latest SNMP CPU utilization percentage (0.0 to 100.0)",
    )
    memory_utilization = models.FloatField(
        null=True,
        blank=True,
        help_text="Latest SNMP Memory utilization percentage (0.0 to 100.0)",
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


class DiscoveryScan(models.Model):
    """
    Tracks an automatic or on-demand VIGIL network discovery scan session.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        STOPPED = "stopped", "Stopped"
        FAILED = "failed", "Failed"

    interface_name = models.CharField(max_length=100, blank=True)
    target_cidr = models.CharField(max_length=64, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    progress_pct = models.PositiveSmallIntegerField(default=0)
    total_hosts_scanned = models.PositiveIntegerField(default=0)
    discovered_count = models.PositiveIntegerField(default=0)
    new_devices_count = models.PositiveIntegerField(default=0)
    changes_detected_count = models.PositiveIntegerField(default=0)
    scan_methods = models.CharField(max_length=120, default="arp,icmp,dns,port")
    started_by = models.ForeignKey(
        "auth.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovery_scans",
    )
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(default=0.0)
    error_message = models.TextField(blank=True)

    class Meta:
        verbose_name = "Discovery Scan"
        verbose_name_plural = "Discovery Scans"
        ordering = ["-started_at"]

    def __str__(self):
        return f"Scan {self.target_cidr} ({self.get_status_display()}) - {self.discovered_count} hosts"


class DiscoveredDevice(models.Model):
    """
    Represents a network asset discovered by VIGIL's automatic discovery engine.
    Kept separate from monitored `Device` records until explicitly registered by an operator,
    while tracking inventory history, confidence scores, and trust status.
    """

    class TrustStatus(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        TRUSTED = "trusted", "Trusted"
        UNTRUSTED = "untrusted", "Untrusted"
        IGNORED = "ignored", "Ignored"
        MONITORED = "monitored", "Monitored"

    class HostnameSource(models.TextChoices):
        MANUAL = "manual", "Manual Override"
        SNMP = "snmp", "SNMP sysName"
        LOCAL = "local", "Local Host OS"
        DHCP = "dhcp", "Router DHCP / DNS"
        PTR = "ptr", "Reverse DNS (PTR)"
        MDNS = "mdns", "mDNS (.local)"
        NETBIOS = "netbios", "NetBIOS (NBNS)"
        LLMNR = "llmnr", "LLMNR"
        NMAP = "nmap", "Nmap Discovery"
        NONE = "none", "Not Resolved"

    class MacAddressType(models.TextChoices):
        GLOBAL = "global", "Globally Administered (IEEE OUI)"
        LOCALLY_ADMINISTERED = "locally_administered", "Locally Administered MAC"
        RANDOMIZED_LIKELY = "randomized_likely", "Randomized / Private MAC (likely)"
        MULTICAST = "multicast", "Multicast MAC"
        UNKNOWN = "unknown", "Unknown"

    class IdentificationStatus(models.TextChoices):
        IDENTIFIED = "identified", "Identified"
        PARTIAL = "partial", "Partial Identification"
        PENDING = "pending", "Identification Pending"
        MANUAL = "manual", "Manually Verified"

    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=False,
        unique=True,
        db_index=True,
    )
    mac_address = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        db_index=True,
    )
    hostname = models.CharField(max_length=150, blank=True)
    hostname_source = models.CharField(
        max_length=30,
        choices=HostnameSource.choices,
        default=HostnameSource.NONE,
        blank=True,
    )
    hostname_manually_set = models.BooleanField(
        default=False,
        help_text="True if an operator manually assigned this hostname",
    )
    discovered_hostnames = models.JSONField(
        default=dict,
        blank=True,
        help_text="Dictionary of all hostnames resolved per method (e.g. {'netbios': 'PC1', 'ptr': 'pc1.lan'})",
    )
    mac_address_type = models.CharField(
        max_length=30,
        choices=MacAddressType.choices,
        default=MacAddressType.UNKNOWN,
        blank=True,
    )
    mac_vendor = models.CharField(
        max_length=150,
        blank=True,
        help_text="Registered IEEE MAC vendor or LAA status",
    )
    manufacturer = models.CharField(max_length=150, blank=True)
    estimated_brand = models.CharField(
        max_length=120,
        blank=True,
        help_text="Estimated device brand (distinct from NIC/wireless chipset manufacturer)",
    )
    is_chipset_oem = models.BooleanField(
        default=False,
        help_text="True if the MAC vendor is a network interface/chipset OEM (Intel, MediaTek, AltoBeam, etc.)",
    )
    device_type = models.CharField(
        max_length=30,
        choices=Device.DeviceType.choices,
        default=Device.DeviceType.UNKNOWN,
        db_index=True,
    )
    type_manually_set = models.BooleanField(
        default=False,
        help_text="True if an operator manually overrode the device type classification",
    )
    confidence_score = models.PositiveSmallIntegerField(
        default=0,
        help_text="Identification confidence percentage (0 to 100)",
    )
    classification_reason = models.CharField(max_length=255, blank=True)
    identification_status = models.CharField(
        max_length=25,
        choices=IdentificationStatus.choices,
        default=IdentificationStatus.PENDING,
        db_index=True,
    )
    discovery_methods = models.CharField(
        max_length=120,
        default="arp,icmp",
        help_text="Comma-separated discovery techniques that detected this host",
    )
    is_reachable = models.BooleanField(default=True, db_index=True)
    latency_ms = models.FloatField(null=True, blank=True)
    open_ports = models.CharField(max_length=150, blank=True)
    sys_description = models.TextField(blank=True)
    sys_object_id = models.CharField(max_length=150, blank=True)
    subnet_cidr = models.CharField(max_length=64, blank=True, db_index=True)
    interface_name = models.CharField(max_length=100, blank=True)

    trust_status = models.CharField(
        max_length=20,
        choices=TrustStatus.choices,
        default=TrustStatus.UNKNOWN,
        db_index=True,
    )
    monitored_device = models.ForeignKey(
        Device,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovered_entries",
    )
    last_scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="devices_found",
    )
    last_hostname_resolved_at = models.DateTimeField(null=True, blank=True)
    last_vendor_lookup_at = models.DateTimeField(null=True, blank=True)
    first_discovered_at = models.DateTimeField(auto_now_add=True)
    last_discovered_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        verbose_name = "Discovered Device"
        verbose_name_plural = "Discovered Devices"
        ordering = ["-last_discovered_at", "ip_address"]
        indexes = [
            models.Index(fields=["trust_status", "is_reachable"]),
            models.Index(fields=["subnet_cidr", "is_reachable"]),
        ]

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.get_device_type_display()}) [{self.get_trust_status_display()}]"

    @property
    def confidence_label(self) -> str:
        if self.confidence_score >= 80:
            return "High"
        if self.confidence_score >= 50:
            return "Medium"
        if self.confidence_score > 0:
            return "Low"
        return "Unknown"

    @property
    def mac_vendor_display(self) -> str:
        if self.mac_vendor:
            return self.mac_vendor
        if self.manufacturer:
            return self.manufacturer
        if self.mac_address_type in (self.MacAddressType.LOCALLY_ADMINISTERED, self.MacAddressType.RANDOMIZED_LIKELY):
            return "Locally Administered MAC"
        return "Unknown Vendor"

    @property
    def is_monitored(self) -> bool:
        return self.monitored_device_id is not None or self.trust_status == self.TrustStatus.MONITORED

    def register_for_monitoring(self, custom_name: Optional[str] = None, location: str = "") -> Device:
        """
        Promotes or links this DiscoveredDevice to a monitored Device record
        without creating duplicate IP or hostname registrations.
        """
        existing = Device.objects.filter(ip_address=self.ip_address).first()
        if not existing and self.mac_address:
            existing = Device.objects.filter(mac_address__iexact=self.mac_address).first()

        if existing:
            if self.mac_address and not existing.mac_address:
                existing.mac_address = self.mac_address
            if self.hostname and not existing.hostname:
                existing.hostname = self.hostname
            if self.manufacturer and not existing.manufacturer:
                existing.manufacturer = self.manufacturer
            existing.save()
            self.monitored_device = existing
            self.trust_status = self.TrustStatus.MONITORED
            self.save(update_fields=["monitored_device", "trust_status"])
            return existing

        base_name = custom_name or self.hostname or f"Host-{self.ip_address.replace('.', '-')}"
        candidate_name = base_name[:115]
        suffix = 1
        while Device.objects.filter(name=candidate_name).exists():
            suffix += 1
            candidate_name = f"{base_name[:105]}-{suffix}"

        dev_type = self.device_type if self.device_type != Device.DeviceType.UNKNOWN else Device.DeviceType.OTHER
        new_device = Device.objects.create(
            name=candidate_name,
            ip_address=self.ip_address,
            mac_address=self.mac_address if self.mac_address else None,
            device_type=dev_type,
            hostname=self.hostname,
            manufacturer=self.manufacturer,
            sys_description=self.sys_description,
            sys_object_id=self.sys_object_id,
            location=location or (f"Subnet {self.subnet_cidr}" if self.subnet_cidr else "Discovered Network"),
            status=Device.Status.ONLINE if self.is_reachable else Device.Status.UNKNOWN,
            monitoring_enabled=True,
            last_checked=timezone.now(),
        )
        self.monitored_device = new_device
        self.trust_status = self.TrustStatus.MONITORED
        self.save(update_fields=["monitored_device", "trust_status"])
        return new_device


class NetworkChangeEvent(models.Model):
    """
    Records network inventory changes detected across discovery sweeps:
    new devices, disappeared devices, returning devices, IP changes, MAC changes,
    hostname changes, and device classification changes.
    """

    class EventType(models.TextChoices):
        NEW_DEVICE = "new_device", "Newly Discovered Device"
        DEVICE_DISAPPEARED = "device_disappeared", "Device Disappeared"
        DEVICE_RETURNED = "device_returned", "Device Returned to Network"
        IP_CHANGED = "ip_changed", "IP Address Changed"
        MAC_CHANGED = "mac_changed", "MAC Address Changed"
        HOSTNAME_CHANGED = "hostname_changed", "Hostname Changed"
        TYPE_CHANGED = "type_changed", "Device Type Changed"

    class Severity(models.TextChoices):
        INFO = "info", "Informational"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    discovered_device = models.ForeignKey(
        DiscoveredDevice,
        on_delete=models.CASCADE,
        related_name="change_events",
        null=True,
        blank=True,
    )
    event_type = models.CharField(
        max_length=40,
        choices=EventType.choices,
        db_index=True,
    )
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.INFO,
        db_index=True,
    )
    previous_value = models.CharField(max_length=255, blank=True)
    new_value = models.CharField(max_length=255, blank=True)
    description = models.TextField()
    is_acknowledged = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        verbose_name = "Network Change Event"
        verbose_name_plural = "Network Change Events"
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.get_event_type_display()}] {self.description[:80]}"
