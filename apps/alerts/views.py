from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, TemplateView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Alert, AlertThreshold
from .serializers import AlertSerializer, AlertThresholdSerializer
from accounts.permissions import OperatorRequiredMixin


class AlertListView(LoginRequiredMixin, ListView):
    """
    Incident and alert management dashboard.
    Lists active and historical alarms with severity filtering and acknowledgement action.
    """
    model = Alert
    template_name = "alerts/alert_list.html"
    context_object_name = "alerts"
    paginate_by = 25
    login_url = "accounts:login"

    def get_queryset(self):
        qs = Alert.objects.select_related("device", "acknowledged_by").order_by("-created_at")
        tab = self.request.GET.get("tab", "active")
        severity = self.request.GET.get("severity")
        alert_type = self.request.GET.get("alert_type")

        if tab == "active":
            qs = qs.filter(is_resolved=False)
        elif tab == "resolved":
            qs = qs.filter(is_resolved=True)
        elif tab == "unacknowledged":
            qs = qs.filter(is_acknowledged=False, is_resolved=False)

        if severity:
            qs = qs.filter(severity=severity)
        if alert_type:
            qs = qs.filter(alert_type=alert_type)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["current_tab"] = self.request.GET.get("tab", "active")
        ctx["current_severity"] = self.request.GET.get("severity", "")
        ctx["current_type"] = self.request.GET.get("alert_type", "")
        ctx["severity_choices"] = Alert.Severity.choices
        ctx["type_choices"] = Alert.AlertType.choices

        # Counts
        all_alerts = Alert.objects.all()
        ctx["active_count"] = all_alerts.filter(is_resolved=False).count()
        ctx["unack_count"] = all_alerts.filter(is_acknowledged=False, is_resolved=False).count()
        ctx["resolved_count"] = all_alerts.filter(is_resolved=True).count()
        ctx["critical_count"] = all_alerts.filter(is_resolved=False, severity=Alert.Severity.CRITICAL).count()
        ctx["warning_count"] = all_alerts.filter(is_resolved=False, severity=Alert.Severity.WARNING).count()
        return ctx

    def post(self, request, *args, **kwargs):
        """Handle alert acknowledgement via form POST."""
        if not (hasattr(request.user, "profile") and request.user.profile.is_operator):
            messages.error(request, "Only operators can acknowledge alerts.")
            return redirect("alerts:alert-list")

        alert_id = request.POST.get("alert_id")
        action_type = request.POST.get("action")

        if alert_id:
            alert = get_object_or_404(Alert, id=alert_id)
            if action_type == "acknowledge":
                alert.acknowledge(request.user)
                messages.success(request, f"Alert #{alert.id} ({alert.device.name}) acknowledged.")
            elif action_type == "resolve":
                alert.resolve()
                messages.success(request, f"Alert #{alert.id} ({alert.device.name}) marked as resolved.")

        return redirect(request.get_full_path())


class SettingsView(OperatorRequiredMixin, TemplateView):
    """
    Monitoring configuration and Alert Thresholds settings view.
    """
    template_name = "alerts/settings.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
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
        ctx["threshold"] = threshold
        return ctx

    def post(self, request, *args, **kwargs):
        threshold, _ = AlertThreshold.objects.get_or_create(name="Default Global Thresholds")
        try:
            threshold.high_latency_warning_ms = float(request.POST.get("high_latency_warning_ms", 100.0))
            threshold.high_latency_critical_ms = float(request.POST.get("high_latency_critical_ms", 300.0))
            threshold.packet_loss_warning_pct = float(request.POST.get("packet_loss_warning_pct", 5.0))
            threshold.packet_loss_critical_pct = float(request.POST.get("packet_loss_critical_pct", 25.0))
            threshold.consecutive_failures_for_offline = int(request.POST.get("consecutive_failures_for_offline", 3))
            threshold.save()
            messages.success(request, "Monitoring alert thresholds updated successfully.")
        except (ValueError, TypeError) as exc:
            messages.error(request, f"Invalid value provided: {exc}")
        return redirect("alerts:settings")


class AlertViewSet(viewsets.ModelViewSet):
    """
    API for monitoring alerts, severity filtering, and operator acknowledgement.
    """
    queryset = Alert.objects.all().order_by("-created_at")
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        status_param = self.request.query_params.get("resolved")
        severity_param = self.request.query_params.get("severity")
        device_id = self.request.query_params.get("device_id")

        if status_param is not None:
            qs = qs.filter(is_resolved=status_param.lower() in ("true", "1"))
        if severity_param:
            qs = qs.filter(severity=severity_param)
        if device_id:
            qs = qs.filter(device_id=device_id)
        return qs

    @action(detail=True, methods=["post"], url_path="acknowledge")
    def acknowledge(self, request, pk=None):
        """Allows an operator to acknowledge an active incident."""
        alert = self.get_object()
        if alert.is_acknowledged:
            return Response(
                {"detail": "Alert is already acknowledged."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        alert.acknowledge(request.user)
        return Response(
            {
                "detail": "Alert successfully acknowledged.",
                "acknowledged_by": request.user.username,
                "acknowledged_at": alert.acknowledged_at,
            },
            status=status.HTTP_200_OK,
        )


class AlertThresholdViewSet(viewsets.ModelViewSet):
    queryset = AlertThreshold.objects.all()
    serializer_class = AlertThresholdSerializer
    permission_classes = [permissions.IsAuthenticated]
