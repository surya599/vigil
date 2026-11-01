from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView
from django.db.models import Avg, Min, Max, Count
from rest_framework import viewsets, permissions, generics

from devices.models import Device
from .models import DeviceMetric, NetworkInterface, InterfaceMetric
from .serializers import (
    DeviceMetricSerializer,
    NetworkInterfaceSerializer,
    InterfaceMetricSerializer,
)


class PerformanceMonitoringView(LoginRequiredMixin, TemplateView):
    """
    Performance monitoring view displaying latency trends, packet loss,
    and jitter analytics across all registered devices.
    """
    template_name = "monitoring/performance.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        devices = Device.objects.filter(monitoring_enabled=True).order_by("name")
        selected_device_id = self.request.GET.get("device")
        
        selected_device = None
        if selected_device_id and selected_device_id.isdigit():
            selected_device = devices.filter(id=int(selected_device_id)).first()
        if not selected_device and devices.exists():
            selected_device = devices.first()

        ctx["devices"] = devices
        ctx["selected_device"] = selected_device
        ctx["selected_range"] = self.request.GET.get("range", "24h")

        # Device performance summary
        if selected_device:
            metrics_qs = selected_device.metrics.all()
            agg = metrics_qs.aggregate(
                avg_lat=Avg("latency"),
                min_lat=Min("latency"),
                max_lat=Max("latency"),
                avg_jitter=Avg("jitter"),
                avg_loss=Avg("packet_loss"),
                total_checks=Count("id"),
            )
            ctx["avg_latency"] = round(agg["avg_lat"] or 0.0, 1)
            ctx["min_latency"] = round(agg["min_lat"] or 0.0, 1)
            ctx["max_latency"] = round(agg["max_lat"] or 0.0, 1)
            ctx["avg_jitter"] = round(agg["avg_jitter"] or 0.0, 2)
            ctx["avg_loss"] = round(agg["avg_loss"] or 0.0, 1)
            ctx["total_checks"] = agg["total_checks"] or 0
            ctx["daily_summaries"] = selected_device.daily_summaries.order_by("-date")[:14]
        return ctx


class MonitoringHistoryView(LoginRequiredMixin, ListView):
    """
    Tabular log history of ICMP and SNMP polling events.
    Supports device filtering, status filtering, and pagination.
    """
    model = DeviceMetric
    template_name = "monitoring/history.html"
    context_object_name = "metrics"
    paginate_by = 30
    login_url = "accounts:login"

    def get_queryset(self):
        qs = DeviceMetric.objects.select_related("device").order_by("-recorded_at")
        device_id = self.request.GET.get("device")
        status_filter = self.request.GET.get("status")
        
        if device_id and device_id.isdigit():
            qs = qs.filter(device_id=int(device_id))
        if status_filter:
            qs = qs.filter(status=status_filter)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["devices"] = Device.objects.order_by("name")
        ctx["selected_device"] = self.request.GET.get("device", "")
        ctx["selected_status"] = self.request.GET.get("status", "")
        ctx["status_choices"] = DeviceMetric.Status.choices
        return ctx


class DeviceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only API for historical device latency & packet loss metrics.
    """
    queryset = DeviceMetric.objects.all().order_by("-recorded_at")
    serializer_class = DeviceMetricSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        device_id = self.request.query_params.get("device_id")
        if device_id:
            qs = qs.filter(device_id=device_id)
        limit = self.request.query_params.get("limit")
        if limit and limit.isdigit():
            qs = qs[:int(limit)]
        return qs


class NetworkInterfaceViewSet(viewsets.ModelViewSet):
    """
    API for managing device network interfaces.
    """
    queryset = NetworkInterface.objects.all().order_by("device", "interface_index")
    serializer_class = NetworkInterfaceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        device_id = self.request.query_params.get("device_id")
        if device_id:
            qs = qs.filter(device_id=device_id)
        return qs


class InterfaceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API for historical interface bandwidth metrics.
    """
    queryset = InterfaceMetric.objects.all().order_by("-recorded_at")
    serializer_class = InterfaceMetricSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        interface_id = self.request.query_params.get("interface_id")
        if interface_id:
            qs = qs.filter(interface_id=interface_id)
        return qs
