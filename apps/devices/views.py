from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib import messages
from django.db.models import Q
from django.shortcuts import redirect
from rest_framework import viewsets, permissions, filters

from .models import Device
from .forms import DeviceForm
from .serializers import DeviceSerializer
from accounts.permissions import OperatorRequiredMixin


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


# ─── REST API ViewSet ────────────────────────────────────────────────────────

class DeviceViewSet(viewsets.ModelViewSet):
    """REST API for network devices — filterable by status, device_type, and search."""
    queryset = Device.objects.all().order_by("-updated_at")
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]
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
