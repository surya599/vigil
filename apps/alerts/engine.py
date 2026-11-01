"""
NetPulse Incident Alert Generation, Escalation & Self-Healing Engine.

Provides:
1. Deduplicated alert creation with automatic severity escalation (WARNING -> CRITICAL)
2. Bandwidth threshold evaluation (THRESHOLD_EXCEEDED alerts on high link utilization)
3. Self-healing auto-resolution when telemetry normalizes
4. NOC Incident KPI computation: Mean Time To Acknowledge (MTTA) and Mean Time To Resolve (MTTR)
"""

import logging
from datetime import timedelta
from typing import Optional

from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F
from django.utils import timezone

from monitoring.broadcaster import broadcast_alert_event
from .models import Alert, AlertThreshold

logger = logging.getLogger("netpulse.alerts.engine")


class AlertEngine:
    """
    Centralized engine for creating, escalating, acknowledging, and resolving
    network incident alerts across ICMP, SNMP, and bandwidth monitors.
    """

    DEFAULT_BANDWIDTH_UTILIZATION_THRESHOLD_PCT = 85.0

    @staticmethod
    def get_active_threshold() -> AlertThreshold:
        """Retrieves the active AlertThreshold profile, creating default if none exists."""
        threshold = AlertThreshold.objects.filter(is_active=True).first()
        if not threshold:
            threshold, _ = AlertThreshold.objects.get_or_create(
                name="Default Global Thresholds",
                defaults={
                    "high_latency_warning_ms": 100.0,
                    "high_latency_critical_ms": 300.0,
                    "packet_loss_warning_pct": 5.0,
                    "packet_loss_critical_pct": 25.0,
                    "consecutive_failures_for_offline": 3,
                    "is_active": True,
                },
            )
        return threshold

    @classmethod
    def trigger_or_escalate_alert(
        cls,
        device,
        alert_type: str,
        severity: str,
        description: str,
        interface_name: Optional[str] = None,
    ) -> tuple:
        """
        Creates a new Alert if no active (unresolved) alert of the same type exists
        for the device (and optional interface_name).
        If an active alert exists with a lower severity (e.g. WARNING -> CRITICAL),
        escalates the existing alert in-place and broadcasts the update.
        Returns (alert, created_or_escalated: bool).
        """
        now = timezone.now()
        qs = Alert.objects.filter(
            device=device,
            alert_type=alert_type,
            is_resolved=False,
        )
        if interface_name:
            qs = qs.filter(description__icontains=f"'{interface_name}'")

        existing = qs.first()
        if existing:
            # Check for severity escalation (info -> warning -> critical)
            rank = {
                Alert.Severity.INFO: 1,
                Alert.Severity.WARNING: 2,
                Alert.Severity.CRITICAL: 3,
            }
            if rank.get(severity, 0) > rank.get(existing.severity, 0):
                existing.severity = severity
                existing.description = description
                existing.save(update_fields=["severity", "description"])
                broadcast_alert_event(existing, event="created")
                logger.warning(
                    "Escalated alert #%d on '%s' to %s",
                    existing.id,
                    device.name,
                    severity,
                )
                return existing, True
            return existing, False

        alert = Alert.objects.create(
            device=device,
            alert_type=alert_type,
            severity=severity,
            description=description,
            created_at=now,
        )
        broadcast_alert_event(alert, event="created")
        logger.warning(
            "Triggered %s %s alert #%d for '%s'",
            severity.upper(),
            alert_type,
            alert.id,
            device.name,
        )
        return alert, True

    @classmethod
    def auto_resolve_alerts(
        cls,
        device,
        alert_type: str,
        interface_name: Optional[str] = None,
    ) -> int:
        """
        Resolves all active alerts matching (device, alert_type, [interface_name])
        and broadcasts a 'resolved' WebSocket event for each.
        Returns count of resolved alerts.
        """
        qs = Alert.objects.filter(
            device=device,
            alert_type=alert_type,
            is_resolved=False,
        )
        if interface_name:
            qs = qs.filter(description__icontains=f"'{interface_name}'")

        count = 0
        for alert in qs:
            alert.resolve()
            count += 1
        return count

    @classmethod
    def evaluate_interface_bandwidth(
        cls,
        device,
        interface,
        in_bps: float,
        out_bps: float,
        utilization_threshold_pct: float = DEFAULT_BANDWIDTH_UTILIZATION_THRESHOLD_PCT,
    ):
        """
        Evaluates whether an interface's traffic rate exceeds the bandwidth utilization
        threshold (default 85% of configured speed_bps).
        Triggers or auto-resolves THRESHOLD_EXCEEDED alerts accordingly.
        """
        if not interface.speed_bps or interface.speed_bps <= 0:
            return None

        peak_bps = max(in_bps or 0.0, out_bps or 0.0)
        utilization_pct = round((peak_bps / float(interface.speed_bps)) * 100.0, 1)

        if utilization_pct >= utilization_threshold_pct:
            severity = (
                Alert.Severity.CRITICAL if utilization_pct >= 95.0 else Alert.Severity.WARNING
            )
            peak_mbps = round(peak_bps / 1_000_000.0, 2)
            speed_mbps = round(interface.speed_bps / 1_000_000.0, 1)
            description = (
                f"Bandwidth threshold exceeded on interface '{interface.interface_name}' "
                f"of '{device.name}' ({device.ip_address}): {utilization_pct}% utilization "
                f"({peak_mbps} Mbps / {speed_mbps} Mbps)."
            )
            alert, _ = cls.trigger_or_escalate_alert(
                device=device,
                alert_type=Alert.AlertType.THRESHOLD_EXCEEDED,
                severity=severity,
                description=description,
                interface_name=interface.interface_name,
            )
            return alert
        else:
            cls.auto_resolve_alerts(
                device=device,
                alert_type=Alert.AlertType.THRESHOLD_EXCEEDED,
                interface_name=interface.interface_name,
            )
            return None

    @staticmethod
    def compute_incident_kpis() -> dict:
        """
        Calculates NOC incident management KPIs:
        - Active, Unacknowledged, Critical, Warning, Info, and Resolved counts
        - Mean Time To Acknowledge (MTTA) in minutes
        - Mean Time To Resolve (MTTR) in minutes
        - Breakdown by alert_type
        """
        all_alerts = Alert.objects.all()
        active_qs = all_alerts.filter(is_resolved=False)

        # Compute MTTA across acknowledged alerts
        ack_alerts = all_alerts.filter(
            is_acknowledged=True,
            acknowledged_at__isnull=False,
        ).annotate(
            ack_delta=ExpressionWrapper(
                F("acknowledged_at") - F("created_at"),
                output_field=DurationField(),
            )
        )
        mtta_agg = ack_alerts.aggregate(avg_delta=Avg("ack_delta"))
        mtta_seconds = mtta_agg["avg_delta"].total_seconds() if mtta_agg["avg_delta"] else 0.0
        mtta_minutes = round(max(0.0, mtta_seconds) / 60.0, 1)

        # Compute MTTR across resolved alerts
        resolved_alerts = all_alerts.filter(
            is_resolved=True,
            resolved_at__isnull=False,
        ).annotate(
            res_delta=ExpressionWrapper(
                F("resolved_at") - F("created_at"),
                output_field=DurationField(),
            )
        )
        mttr_agg = resolved_alerts.aggregate(avg_delta=Avg("res_delta"))
        mttr_seconds = mttr_agg["avg_delta"].total_seconds() if mttr_agg["avg_delta"] else 0.0
        mttr_minutes = round(max(0.0, mttr_seconds) / 60.0, 1)

        by_type = {}
        for key, label in Alert.AlertType.choices:
            by_type[key] = active_qs.filter(alert_type=key).count()

        return {
            "active_count": active_qs.count(),
            "unacknowledged_count": active_qs.filter(is_acknowledged=False).count(),
            "acknowledged_active_count": active_qs.filter(is_acknowledged=True).count(),
            "resolved_count": all_alerts.filter(is_resolved=True).count(),
            "critical_count": active_qs.filter(severity=Alert.Severity.CRITICAL).count(),
            "warning_count": active_qs.filter(severity=Alert.Severity.WARNING).count(),
            "info_count": active_qs.filter(severity=Alert.Severity.INFO).count(),
            "mtta_minutes": mtta_minutes,
            "mttr_minutes": mttr_minutes,
            "active_by_type": by_type,
        }
