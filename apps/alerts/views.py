from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import ListView, TemplateView
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.permissions import OperatorRequiredMixin
from devices.models import Device
from .engine import AlertEngine
from .models import Alert, AlertThreshold
from .serializers import AlertSerializer, AlertThresholdSerializer


class AlertListView(LoginRequiredMixin, ListView):
    """
    Incident and alert management dashboard.
    Lists active and historical alarms with severity, type, device, and search filtering,
    plus single and bulk operator acknowledgement/resolution workflows.
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
        device_id = self.request.GET.get("device")
        search_q = self.request.GET.get("q", "").strip()

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
        if device_id and str(device_id).isdigit():
            qs = qs.filter(device_id=int(device_id))
        if search_q:
            qs = qs.filter(
                Q(description__icontains=search_q)
                | Q(device__name__icontains=search_q)
                | Q(device__ip_address__icontains=search_q)
            )
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["current_tab"] = self.request.GET.get("tab", "active")
        ctx["current_severity"] = self.request.GET.get("severity", "")
        ctx["current_type"] = self.request.GET.get("alert_type", "")
        ctx["current_device"] = self.request.GET.get("device", "")
        ctx["search_query"] = self.request.GET.get("q", "")
        ctx["severity_choices"] = Alert.Severity.choices
        ctx["type_choices"] = Alert.AlertType.choices
        ctx["devices"] = Device.objects.order_by("name")

        # Counts & Operational KPIs (MTTA / MTTR)
        kpis = AlertEngine.compute_incident_kpis()
        ctx["active_count"] = kpis["active_count"]
        ctx["unack_count"] = kpis["unacknowledged_count"]
        ctx["resolved_count"] = kpis["resolved_count"]
        ctx["critical_count"] = kpis["critical_count"]
        ctx["warning_count"] = kpis["warning_count"]
        ctx["mtta_minutes"] = kpis["mtta_minutes"]
        ctx["mttr_minutes"] = kpis["mttr_minutes"]
        return ctx

    def post(self, request, *args, **kwargs):
        """Handle single and bulk alert acknowledgement/resolution via form POST."""
        if not (hasattr(request.user, "profile") and request.user.profile.is_operator):
            messages.error(request, "Only operators can acknowledge or resolve alerts.")
            return redirect("alerts:alert-list")

        alert_id = request.POST.get("alert_id")
        action_type = request.POST.get("action")

        if action_type == "acknowledge_all":
            unack_qs = Alert.objects.filter(is_resolved=False, is_acknowledged=False)
            count = 0
            for alert in unack_qs:
                alert.acknowledge(request.user)
                count += 1
            messages.success(request, f"Acknowledged {count} active incident(s).")
        elif action_type == "resolve_all":
            active_qs = Alert.objects.filter(is_resolved=False)
            count = 0
            for alert in active_qs:
                alert.resolve()
                count += 1
            messages.success(request, f"Resolved {count} active incident(s).")
        elif alert_id:
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
        ctx["threshold"] = AlertEngine.get_active_threshold()
        return ctx

    def post(self, request, *args, **kwargs):
        threshold, _ = AlertThreshold.objects.get_or_create(name="Default Global Thresholds")
        try:
            threshold.high_latency_warning_ms = float(request.POST.get("high_latency_warning_ms", 100.0))
            threshold.high_latency_critical_ms = float(request.POST.get("high_latency_critical_ms", 300.0))
            threshold.packet_loss_warning_pct = float(request.POST.get("packet_loss_warning_pct", 5.0))
            threshold.packet_loss_critical_pct = float(request.POST.get("packet_loss_critical_pct", 25.0))
            threshold.consecutive_failures_for_offline = int(
                request.POST.get("consecutive_failures_for_offline", 3)
            )
            threshold.save()
            messages.success(request, "Monitoring alert thresholds updated successfully.")
        except (ValueError, TypeError) as exc:
            messages.error(request, f"Invalid value provided: {exc}")
        return redirect("alerts:settings")


class AlertViewSet(viewsets.ModelViewSet):
    """
    API for monitoring alerts, severity filtering, operator acknowledgement,
    manual resolution, bulk actions, and MTTA/MTTR summary KPIs.
    """

    queryset = Alert.objects.select_related("device", "acknowledged_by").order_by("-created_at")
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        status_param = self.request.query_params.get("resolved")
        ack_param = self.request.query_params.get("acknowledged")
        severity_param = self.request.query_params.get("severity")
        alert_type_param = self.request.query_params.get("alert_type")
        device_id = self.request.query_params.get("device_id")

        if status_param is not None:
            qs = qs.filter(is_resolved=status_param.lower() in ("true", "1"))
        if ack_param is not None:
            qs = qs.filter(is_acknowledged=ack_param.lower() in ("true", "1"))
        if severity_param:
            qs = qs.filter(severity=severity_param)
        if alert_type_param:
            qs = qs.filter(alert_type=alert_type_param)
        if device_id:
            qs = qs.filter(device_id=device_id)
        return qs

    @staticmethod
    def _is_operator(user) -> bool:
        return bool(user.is_superuser or (hasattr(user, "profile") and user.profile.is_operator))

    @action(detail=True, methods=["post"], url_path="acknowledge")
    def acknowledge(self, request, pk=None):
        """Allows an operator or administrator to acknowledge an active incident."""
        if not self._is_operator(request.user):
            return Response(
                {"detail": "Only operators or administrators can acknowledge alerts."},
                status=status.HTTP_403_FORBIDDEN,
            )

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
                "alert_id": alert.id,
                "acknowledged_by": request.user.username,
                "acknowledged_at": alert.acknowledged_at,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"], url_path="resolve")
    def resolve(self, request, pk=None):
        """Allows an operator or administrator to manually resolve an active incident."""
        if not self._is_operator(request.user):
            return Response(
                {"detail": "Only operators or administrators can resolve alerts."},
                status=status.HTTP_403_FORBIDDEN,
            )

        alert = self.get_object()
        if alert.is_resolved:
            return Response(
                {"detail": "Alert is already resolved."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        alert.resolve()
        return Response(
            {
                "detail": "Alert successfully resolved.",
                "alert_id": alert.id,
                "resolved_at": alert.resolved_at,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="bulk-action")
    def bulk_action(self, request):
        """
        Executes bulk 'acknowledge' or 'resolve' across specified alert_ids
        (or all active alerts if alert_ids is omitted).
        """
        if not self._is_operator(request.user):
            return Response(
                {"detail": "Only operators or administrators can perform bulk alert actions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        action_type = request.data.get("action")
        alert_ids = request.data.get("alert_ids")

        if action_type not in ("acknowledge", "resolve"):
            return Response(
                {"detail": "Invalid action. Must be 'acknowledge' or 'resolve'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = Alert.objects.filter(is_resolved=False)
        if isinstance(alert_ids, list) and alert_ids:
            qs = qs.filter(id__in=alert_ids)

        processed = 0
        if action_type == "acknowledge":
            for alert in qs.filter(is_acknowledged=False):
                alert.acknowledge(request.user)
                processed += 1
        elif action_type == "resolve":
            for alert in qs:
                alert.resolve()
                processed += 1

        return Response(
            {
                "status": "success",
                "action": action_type,
                "processed_count": processed,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"], url_path="summary")
    def summary(self, request):
        """Returns NOC incident management KPIs including MTTA, MTTR, and breakdowns."""
        return Response(AlertEngine.compute_incident_kpis(), status=status.HTTP_200_OK)


class AlertThresholdViewSet(viewsets.ModelViewSet):
    queryset = AlertThreshold.objects.all()
    serializer_class = AlertThresholdSerializer
    permission_classes = [permissions.IsAuthenticated]
