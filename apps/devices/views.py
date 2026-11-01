from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy, reverse
from django.contrib import messages
from django.db.models import Q
from django.shortcuts import redirect, get_object_or_404
from django.http import JsonResponse
from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Device
from .forms import DeviceForm
from .serializers import DeviceSerializer
from accounts.permissions import OperatorRequiredMixin, IsOperatorOrReadOnly


class DeviceListView(LoginRequiredMixin, ListView):
    """Main network device table with search, status filter, and pagination."""
    model = Device
    template_name = "devices/device_list.html"
    context_object_name = "devices"
    paginate_by = 20
    login_url = "accounts:login"

    def get_queryset(self):
        qs = Device.objects.all().order_by("-updated_at")
        search = self.request.GET.get("q", "").strip()
        status = self.request.GET.get("status", "").strip()
        device_type = self.request.GET.get("device_type", "").strip()

        if search:
            qs = qs.filter(
                Q(name__icontains=search)
                | Q(ip_address__icontains=search)
                | Q(location__icontains=search)
                | Q(mac_address__icontains=search)
            )
        if status:
            qs = qs.filter(status=status)
        if device_type:
            qs = qs.filter(device_type=device_type)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["search_query"] = self.request.GET.get("q", "")
        ctx["status_filter"] = self.request.GET.get("status", "")
        ctx["device_type_filter"] = self.request.GET.get("device_type", "")
        ctx["status_choices"] = Device.Status.choices
        ctx["device_type_choices"] = Device.DeviceType.choices
        ctx["total_devices"] = Device.objects.count()
        ctx["online_count"] = Device.objects.filter(status=Device.Status.ONLINE).count()
        ctx["offline_count"] = Device.objects.filter(status=Device.Status.OFFLINE).count()
        ctx["warning_count"] = Device.objects.filter(status=Device.Status.WARNING).count()
        return ctx


class DeviceDetailView(LoginRequiredMixin, DetailView):
    """Detail view for a single monitored device and its latest metrics."""
    model = Device
    template_name = "devices/device_detail.html"
    context_object_name = "device"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        device = self.object
        ctx["recent_metrics"] = device.metrics.order_by("-recorded_at")[:20]
        ctx["interfaces"] = device.interfaces.order_by("interface_index")
        ctx["recent_alerts"] = device.alerts.filter(is_resolved=False).order_by("-created_at")[:10]
        return ctx


class DeviceCreateView(OperatorRequiredMixin, CreateView):
    """Form view for adding a new network device. Operators and Admins only."""
    model = Device
    form_class = DeviceForm
    template_name = "devices/device_form.html"
    success_url = reverse_lazy("devices:device-list")

    def form_valid(self, form):
        messages.success(
            self.request,
            f"Device '{form.instance.name}' ({form.instance.ip_address}) added successfully. "
            "Monitoring will begin on the next scheduled poll.",
        )
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form_title"] = "Add New Device"
        ctx["form_action"] = "Add Device"
        return ctx


class DeviceUpdateView(OperatorRequiredMixin, UpdateView):
    """Edit an existing device's configuration. Operators and Admins only."""
    model = Device
    form_class = DeviceForm
    template_name = "devices/device_form.html"
    success_url = reverse_lazy("devices:device-list")

    def form_valid(self, form):
        messages.success(
            self.request,
            f"Device '{form.instance.name}' updated successfully.",
        )
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form_title"] = f"Edit Device — {self.object.name}"
        ctx["form_action"] = "Save Changes"
        return ctx


class DeviceDeleteView(OperatorRequiredMixin, DeleteView):
    """Confirm and delete a device along with all its metrics. Operators and Admins only."""
    model = Device
    template_name = "devices/device_confirm_delete.html"
    success_url = reverse_lazy("devices:device-list")

    def form_valid(self, form):
        name = self.object.name
        ip = self.object.ip_address
        response = super().form_valid(form)
        messages.warning(
            self.request,
            f"Device '{name}' ({ip}) and all its monitoring history have been permanently deleted.",
        )
        return response


class DevicePingView(OperatorRequiredMixin, View):
    """Triggers an on-demand ICMP health check for a device and returns result or redirects."""

    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        from monitoring.icmp import ICMPMonitoringEngine

        engine = ICMPMonitoringEngine()
        metric = engine.check_device(device, packet_count=4, timeout=1.0)

        if request.headers.get("x-requested-with") == "XMLHttpRequest" or "application/json" in request.headers.get("accept", ""):
            return JsonResponse({
                "status": metric.status,
                "latency": metric.latency,
                "packet_loss": metric.packet_loss,
                "jitter": metric.jitter,
                "consecutive_failures": device.consecutive_failures,
                "uptime_percentage": float(device.uptime_percentage),
                "recorded_at": metric.recorded_at.isoformat(),
            })

        if metric.status == Device.Status.ONLINE:
            messages.success(
                request,
                f"ICMP check succeeded for '{device.name}' ({device.ip_address}): "
                f"Status: ONLINE | RTT: {metric.latency:.1f}ms | Loss: {metric.packet_loss:.0f}%",
            )
        elif metric.status == Device.Status.WARNING:
            messages.warning(
                request,
                f"ICMP check warning for '{device.name}' ({device.ip_address}): "
                f"Status: WARNING | RTT: {metric.latency or 0.0:.1f}ms | Loss: {metric.packet_loss:.0f}%",
            )
        else:
            messages.error(
                request,
                f"ICMP check failed for '{device.name}' ({device.ip_address}): "
                f"Status: OFFLINE | 100% packet loss (Consecutive failures: {device.consecutive_failures})",
            )

        return redirect("devices:device-detail", pk=device.pk)


class DeviceSnmpPollView(OperatorRequiredMixin, View):
    """Triggers an on-demand SNMP poll for a device and updates interfaces and telemetry."""

    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        if not device.snmp_enabled:
            if request.headers.get("x-requested-with") == "XMLHttpRequest" or "application/json" in request.headers.get("accept", ""):
                return JsonResponse({"error": "SNMP is not enabled on this device"}, status=400)
            messages.warning(request, f"SNMP is not enabled on device '{device.name}'.")
            return redirect("devices:device-detail", pk=device.pk)

        from monitoring.snmp import SNMPMonitoringEngine

        engine = SNMPMonitoringEngine()
        data = engine.poll_device(device, timeout=2.0)

        if request.headers.get("x-requested-with") == "XMLHttpRequest" or "application/json" in request.headers.get("accept", ""):
            return JsonResponse({
                "is_successful": data.is_successful,
                "sys_description": data.sys_description,
                "sys_uptime": data.sys_uptime,
                "interfaces_count": len(data.interfaces),
                "error_message": data.error_message,
            })

        if data.is_successful:
            messages.success(
                request,
                f"SNMP interrogation successful for '{device.name}': "
                f"Discovered {len(data.interfaces)} interface(s). Uptime: {data.sys_uptime}.",
            )
        else:
            messages.error(
                request,
                f"SNMP interrogation failed for '{device.name}': {data.error_message}",
            )

        return redirect("devices:device-detail", pk=device.pk)


# ─── REST API ViewSet ────────────────────────────────────────────────────────

class DeviceViewSet(viewsets.ModelViewSet):
    """REST API for network devices — filterable by status, device_type, and search."""
    queryset = Device.objects.all().order_by("-updated_at")
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated, IsOperatorOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "ip_address", "mac_address", "location"]
    ordering_fields = ["name", "ip_address", "status", "updated_at", "last_checked"]

    def get_queryset(self):
        qs = super().get_queryset()
        status_param = self.request.query_params.get("status")
        device_type_param = self.request.query_params.get("device_type")
        monitoring_param = self.request.query_params.get("monitoring_enabled")

        if status_param:
            qs = qs.filter(status=status_param)
        if device_type_param:
            qs = qs.filter(device_type=device_type_param)
        if monitoring_param is not None:
            qs = qs.filter(monitoring_enabled=monitoring_param.lower() in ("true", "1"))
        return qs

    @action(detail=True, methods=["post"], url_path="ping")
    def ping(self, request, pk=None):
        """On-demand ICMP ping check endpoint for a single device."""
        device = self.get_object()
        from monitoring.icmp import ICMPMonitoringEngine

        engine = ICMPMonitoringEngine()
        try:
            count = int(request.data.get("count", 4))
        except (ValueError, TypeError):
            count = 4
        try:
            timeout = float(request.data.get("timeout", 1.0))
        except (ValueError, TypeError):
            timeout = 1.0

        metric = engine.check_device(device, packet_count=count, timeout=timeout)
        return Response({
            "status": metric.status,
            "latency": metric.latency,
            "packet_loss": metric.packet_loss,
            "jitter": metric.jitter,
            "consecutive_failures": device.consecutive_failures,
            "uptime_percentage": float(device.uptime_percentage),
            "recorded_at": metric.recorded_at.isoformat(),
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="snmp-poll")
    def snmp_poll(self, request, pk=None):
        """On-demand SNMP telemetry and interface collection endpoint."""
        device = self.get_object()
        if not device.snmp_enabled:
            return Response(
                {"error": "SNMP is not enabled on this device"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from monitoring.snmp import SNMPMonitoringEngine

        engine = SNMPMonitoringEngine()
        try:
            timeout = float(request.data.get("timeout", 2.0))
        except (ValueError, TypeError):
            timeout = 2.0

        data = engine.poll_device(device, timeout=timeout)
        if not data.is_successful:
            return Response(
                {
                    "is_successful": False,
                    "error": data.error_message,
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response({
            "is_successful": True,
            "sys_description": data.sys_description,
            "sys_name": data.sys_name,
            "sys_uptime": data.sys_uptime,
            "interfaces": [
                {
                    "index": iface.index,
                    "name": iface.name,
                    "description": iface.description,
                    "mac_address": iface.mac_address,
                    "admin_status": iface.admin_status,
                    "oper_status": iface.oper_status,
                    "speed_bps": iface.speed_bps,
                    "in_octets": iface.in_octets,
                    "out_octets": iface.out_octets,
                }
                for iface in data.interfaces
            ],
        }, status=status.HTTP_200_OK)
