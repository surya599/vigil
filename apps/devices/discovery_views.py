"""
VIGIL Phases 2, 3, 4, 5 & 6: Network Discovery, Interface Detection,
Device Registration & Inventory Change Detection Views and REST APIs.
"""
import threading
import time
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.db import close_old_connections
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response

from accounts.models import AuditLog
from accounts.permissions import IsOperatorOrReadOnly
from .discovery import ACTIVE_SCAN_STOP_FLAGS, NetworkDiscoveryEngine
from .models import Device, DiscoveredDevice, DiscoveryScan, NetworkChangeEvent
from .network_interfaces import NetworkInterfaceDetector
from .serializers import (
    DiscoveredDeviceSerializer,
    DiscoveryScanSerializer,
    NetworkChangeEventSerializer,
)


def _log_audit(user, action_name: str, target_type: str, target_id: str, details: str = "", request=None):
    ip_addr = None
    if request:
        ip_addr = request.META.get("REMOTE_ADDR")
    AuditLog.objects.create(
        user=user if (user and user.is_authenticated) else None,
        action=action_name,
        target_type=target_type,
        target_identifier=str(target_id)[:150],
        details=details,
        ip_address=ip_addr,
    )


def execute_discovery_scan_sync(
    scan: DiscoveryScan,
    host_ips_override=None,
    max_workers: int = 64,
    icmp_timeout: float = 0.25,
    enable_port_probe: bool = True,
) -> DiscoveryScan:
    """
    Executes a DiscoveryScan and persists DiscoveredDevice and NetworkChangeEvent records.
    Can be called by the Celery task or synchronously in eager/targeted mode.
    """
    start_ts = time.monotonic()
    scan.status = DiscoveryScan.Status.RUNNING
    scan.progress_pct = 5
    scan.save(update_fields=["status", "progress_pct"])

    stop_cache_key = f"vigil:scan_stop:{scan.id}"
    ACTIVE_SCAN_STOP_FLAGS.discard(scan.id)

    def _on_progress(pct: int, scanned: int, found: int):
        scan.progress_pct = pct
        scan.total_hosts_scanned = scanned
        if found:
            scan.discovered_count = found
        scan.duration_seconds = round(time.monotonic() - start_ts, 2)
        scan.save(update_fields=["progress_pct", "total_hosts_scanned", "discovered_count", "duration_seconds"])

    def _should_stop() -> bool:
        return (scan.id in ACTIVE_SCAN_STOP_FLAGS) or bool(cache.get(stop_cache_key))

    try:
        engine = NetworkDiscoveryEngine(
            max_workers=max_workers,
            icmp_timeout=icmp_timeout,
            enable_port_probe=enable_port_probe,
        )
        records = engine.scan_subnet(
            cidr_input=scan.target_cidr,
            interface_name=scan.interface_name,
            host_ips_override=host_ips_override,
            progress_callback=_on_progress,
            should_stop_callback=_should_stop,
        )

        if _should_stop():
            scan.status = DiscoveryScan.Status.STOPPED
        else:
            scan.status = DiscoveryScan.Status.COMPLETED
            scan.progress_pct = 100

        sync_summary = NetworkDiscoveryEngine.sync_discovered_inventory(
            records=records,
            subnet_cidr=scan.target_cidr,
            scan_obj=scan,
            full_subnet_scan=(host_ips_override is None and not _should_stop()),
        )
        scan.discovered_count = sync_summary["discovered_total"]
        scan.new_devices_count = sync_summary["new_devices"]
        scan.changes_detected_count = sync_summary["changes_detected"]
        if not scan.total_hosts_scanned:
            scan.total_hosts_scanned = len(host_ips_override) if host_ips_override else len(records)
    except Exception as exc:
        scan.status = DiscoveryScan.Status.FAILED
        scan.error_message = str(exc)
    finally:
        ACTIVE_SCAN_STOP_FLAGS.discard(scan.id)
        scan.completed_at = timezone.now()
        scan.duration_seconds = round(time.monotonic() - start_ts, 2)
        scan.save()

        # Broadcast discovery event over WebSocket
        from monitoring.broadcaster import broadcast_discovery_event
        broadcast_discovery_event(scan)

    return scan


def launch_discovery_scan_background(scan_id: int, host_ips_override=None):
    """
    Launches `execute_discovery_scan_sync` in a non-blocking daemon thread so
    large subnet scans (/24, /23, /22, /20) return immediately to the browser UI
    and allow real-time progress polling and instant Stop Scan cancellation.
    """
    def _runner():
        close_old_connections()
        try:
            scan_obj = DiscoveryScan.objects.filter(pk=scan_id).first()
            if scan_obj:
                execute_discovery_scan_sync(scan_obj, host_ips_override=host_ips_override)
        finally:
            close_old_connections()

    worker = threading.Thread(target=_runner, name=f"vigil-scan-{scan_id}", daemon=True)
    worker.start()
    return worker


class NetworkDiscoveryView(LoginRequiredMixin, TemplateView):
    """
    VIGIL Network Discovery & Inventory Intelligence Dashboard (/discovery/).
    Provides:
    - Automatic local interface & CIDR selector
    - Manual CIDR input with RFC1918 scope validation
    - Start / Stop Scan controls & live progress bar
    - Discovered devices table with search, filters, sorting, confidence badges
    - Single & bulk "Add Selected to Monitoring" registration
    - Unknown Devices & Trust Classification controls (Trusted, Untrusted, Ignored, Monitored)
    - Network Change Events feed
    """

    template_name = "devices/discovery.html"
    login_url = "accounts:login"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        interfaces = NetworkInterfaceDetector.detect_interfaces(include_loopback=False)
        primary_iface = interfaces[0] if interfaces else None

        # Filtering & Sorting parameters
        q = self.request.GET.get("q", "").strip()
        device_type = self.request.GET.get("device_type", "").strip()
        trust_status = self.request.GET.get("trust_status", "").strip()
        reachability = self.request.GET.get("reachability", "").strip()
        sort_by = self.request.GET.get("sort", "-last_discovered_at").strip()

        qs = DiscoveredDevice.objects.select_related("monitored_device", "last_scan")
        if q:
            qs = qs.filter(
                Q(ip_address__icontains=q)
                | Q(mac_address__icontains=q)
                | Q(hostname__icontains=q)
                | Q(manufacturer__icontains=q)
            )
        if device_type:
            qs = qs.filter(device_type=device_type)
        if trust_status:
            qs = qs.filter(trust_status=trust_status)
        if reachability == "reachable":
            qs = qs.filter(is_reachable=True)
        elif reachability == "unreachable":
            qs = qs.filter(is_reachable=False)

        allowed_sorts = {
            "ip_address": "ip_address",
            "-ip_address": "-ip_address",
            "hostname": "hostname",
            "device_type": "device_type",
            "-confidence_score": "-confidence_score",
            "-last_discovered_at": "-last_discovered_at",
        }
        qs = qs.order_by(allowed_sorts.get(sort_by, "-last_discovered_at"))

        latest_scan = DiscoveryScan.objects.order_by("-started_at").first()
        unknown_devices = DiscoveredDevice.objects.filter(
            trust_status=DiscoveredDevice.TrustStatus.UNKNOWN
        ).order_by("-last_discovered_at")[:15]
        recent_changes = NetworkChangeEvent.objects.select_related("discovered_device").order_by("-created_at")[:20]

        ctx.update({
            "detected_interfaces": interfaces,
            "primary_interface": primary_iface,
            "default_cidr": primary_iface.network_cidr if primary_iface else "192.168.1.0/24",
            "discovered_devices": qs[:200],
            "total_discovered": DiscoveredDevice.objects.count(),
            "reachable_discovered": DiscoveredDevice.objects.filter(is_reachable=True).count(),
            "unknown_count": DiscoveredDevice.objects.filter(trust_status=DiscoveredDevice.TrustStatus.UNKNOWN).count(),
            "trusted_count": DiscoveredDevice.objects.filter(trust_status=DiscoveredDevice.TrustStatus.TRUSTED).count(),
            "monitored_linked_count": DiscoveredDevice.objects.filter(trust_status=DiscoveredDevice.TrustStatus.MONITORED).count(),
            "untrusted_count": DiscoveredDevice.objects.filter(trust_status=DiscoveredDevice.TrustStatus.UNTRUSTED).count(),
            "unknown_devices": unknown_devices,
            "recent_changes": recent_changes,
            "latest_scan": latest_scan,
            "device_type_choices": Device.DeviceType.choices,
            "trust_choices": DiscoveredDevice.TrustStatus.choices,
            "search_query": q,
            "current_type": device_type,
            "current_trust": trust_status,
            "current_reachability": reachability,
            "current_sort": sort_by,
        })
        return ctx

    def post(self, request, *args, **kwargs):
        if not (request.user.is_superuser or (hasattr(request.user, "profile") and request.user.profile.is_operator)):
            messages.error(request, "Only operators and administrators can run discovery or modify inventory.")
            return redirect("devices:discovery")

        action_type = request.POST.get("action", "")

        if action_type == "start_scan":
            cidr = request.POST.get("target_cidr", "").strip()
            iface_name = request.POST.get("interface_name", "").strip()
            ok, msg, info = NetworkInterfaceDetector.validate_authorized_cidr(cidr)
            if not ok or not info:
                messages.error(request, msg)
                return redirect("devices:discovery")

            scan = DiscoveryScan.objects.create(
                interface_name=iface_name,
                target_cidr=info["network_cidr"],
                status=DiscoveryScan.Status.PENDING,
                started_by=request.user,
            )
            _log_audit(request.user, "start_discovery_scan", "DiscoveryScan", scan.target_cidr, f"Interface: {iface_name}", request)

            # Dispatch via Celery task (falls back to synchronous execution if Redis broker is offline)
            from monitoring.tasks import task_run_network_discovery
            try:
                task_run_network_discovery.delay(scan.id)
            except Exception:
                execute_discovery_scan_sync(scan)
            scan.refresh_from_db()
            messages.success(
                request,
                f"Discovery scan completed for {scan.target_cidr}: found {scan.discovered_count} device(s) ({scan.new_devices_count} new).",
            )

        elif action_type == "stop_scan":
            scan_id = request.POST.get("scan_id")
            if scan_id and str(scan_id).isdigit():
                scan = get_object_or_404(DiscoveryScan, pk=int(scan_id))
                ACTIVE_SCAN_STOP_FLAGS.add(scan.id)
                cache.set(f"vigil:scan_stop:{scan.id}", True, timeout=120)
                scan.status = DiscoveryScan.Status.STOPPED
                scan.completed_at = timezone.now()
                scan.save(update_fields=["status", "completed_at"])
                _log_audit(request.user, "stop_discovery_scan", "DiscoveryScan", scan.target_cidr, "", request)
                messages.info(request, f"Stopped discovery scan #{scan.id} ({scan.target_cidr}).")
            else:
                running_scans = DiscoveryScan.objects.filter(status__in=["pending", "running"])
                for rs in running_scans:
                    ACTIVE_SCAN_STOP_FLAGS.add(rs.id)
                    cache.set(f"vigil:scan_stop:{rs.id}", True, timeout=120)
                    rs.status = DiscoveryScan.Status.STOPPED
                    rs.completed_at = timezone.now()
                    rs.save(update_fields=["status", "completed_at"])
                messages.info(request, "Stopped active discovery scan(s).")

        elif action_type == "register_selected":
            device_ids = request.POST.getlist("discovered_ids")
            if not device_ids:
                messages.warning(request, "No discovered devices were selected for monitoring.")
                return redirect("devices:discovery")

            registered = 0
            for raw_id in device_ids:
                if str(raw_id).isdigit():
                    d_dev = DiscoveredDevice.objects.filter(pk=int(raw_id)).first()
                    if d_dev:
                        d_dev.register_for_monitoring()
                        registered += 1
            _log_audit(request.user, "register_discovered_devices", "DiscoveredDevice", f"{registered} devices", f"IDs: {device_ids}", request)
            messages.success(request, f"Registered {registered} discovered device(s) into continuous monitoring.")

        elif action_type == "delete_selected":
            device_ids = [int(i) for i in request.POST.getlist("discovered_ids") if str(i).isdigit()]
            if not device_ids:
                messages.warning(request, "No discovered devices were selected for removal.")
                return redirect("devices:discovery")

            qs = DiscoveredDevice.objects.filter(pk__in=device_ids)
            deleted_count = qs.count()
            qs.delete()
            _log_audit(request.user, "delete_discovered_devices", "DiscoveredDevice", f"{deleted_count} devices", f"IDs: {device_ids}", request)
            messages.success(request, f"Removed {deleted_count} selected device(s) from Discovered Network Inventory.")

        elif action_type == "delete_single":
            disc_id = request.POST.get("discovered_id")
            if disc_id and str(disc_id).isdigit():
                d_dev = DiscoveredDevice.objects.filter(pk=int(disc_id)).first()
                if d_dev:
                    ip_addr = d_dev.ip_address
                    d_dev.delete()
                    _log_audit(request.user, "delete_discovered_device", "DiscoveredDevice", ip_addr, f"ID: {disc_id}", request)
                    messages.success(request, f"Removed {ip_addr} from Discovered Network Inventory.")

        elif action_type == "clear_all_discovered":
            total_count = DiscoveredDevice.objects.count()
            DiscoveredDevice.objects.all().delete()
            NetworkChangeEvent.objects.all().delete()
            _log_audit(request.user, "clear_discovered_inventory", "DiscoveredDevice", f"{total_count} devices", "Cleared all discovered inventory", request)
            messages.success(request, f"Cleared all {total_count} device(s) from Discovered Network Inventory.")

        elif action_type == "refresh_identification":
            from devices.discovery import NetworkDiscoveryEngine
            from concurrent.futures import ThreadPoolExecutor

            single_id = request.POST.get("discovered_id", "").strip()
            selected_ids = [int(i) for i in request.POST.getlist("discovered_ids") if str(i).isdigit()]
            if single_id and single_id.isdigit():
                targets = list(DiscoveredDevice.objects.filter(pk=int(single_id)))
            elif selected_ids:
                targets = list(DiscoveredDevice.objects.filter(pk__in=selected_ids))
            else:
                targets = list(DiscoveredDevice.objects.all()[:100])

            if not targets:
                messages.info(request, "No discovered devices available to refresh.")
                return redirect("devices:discovery")

            def _refresh_one(dev_obj):
                from django.db import close_old_connections
                close_old_connections()
                return NetworkDiscoveryEngine.refresh_single_device_identification(dev_obj, probe_network=True)

            with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
                list(pool.map(_refresh_one, targets))

            _log_audit(request.user, "refresh_device_identification", "DiscoveredDevice", f"{len(targets)} devices", "", request)
            messages.success(
                request,
                f"Refreshed multi-method hostname & IEEE MAC OUI vendor identification for {len(targets)} device(s).",
            )

        elif action_type == "update_device":
            from devices.hostname_resolver import HostnameResolver

            disc_id = request.POST.get("discovered_id")
            new_trust = request.POST.get("trust_status")
            new_type = request.POST.get("device_type")
            custom_hostname = request.POST.get("custom_hostname")
            if disc_id and str(disc_id).isdigit():
                d_dev = get_object_or_404(DiscoveredDevice, pk=int(disc_id))
                if custom_hostname is not None:
                    cleaned_hn = custom_hostname.strip()
                    if cleaned_hn:
                        if not HostnameResolver.is_valid_hostname(cleaned_hn, ip_address=d_dev.ip_address):
                            messages.error(request, f"Invalid hostname '{cleaned_hn}' (cannot be an IP address or malformed label).")
                            return redirect("devices:discovery")
                        if cleaned_hn != d_dev.hostname or not d_dev.hostname_manually_set:
                            old_hn = d_dev.hostname
                            d_dev.hostname = cleaned_hn
                            d_dev.hostname_source = DiscoveredDevice.HostnameSource.MANUAL
                            d_dev.hostname_manually_set = True
                            d_dev.last_hostname_resolved_at = timezone.now()
                            dh = dict(d_dev.discovered_hostnames or {})
                            dh["manual"] = cleaned_hn
                            d_dev.discovered_hostnames = dh
                            if old_hn and old_hn != cleaned_hn:
                                NetworkChangeEvent.objects.create(
                                    discovered_device=d_dev,
                                    event_type=NetworkChangeEvent.EventType.HOSTNAME_CHANGED,
                                    severity=NetworkChangeEvent.Severity.INFO,
                                    previous_value=old_hn,
                                    new_value=cleaned_hn,
                                    description=f"Operator {request.user.username} manually assigned hostname '{cleaned_hn}' to {d_dev.ip_address}.",
                                )
                if new_trust in dict(DiscoveredDevice.TrustStatus.choices):
                    d_dev.trust_status = new_trust
                    if new_trust == DiscoveredDevice.TrustStatus.MONITORED:
                        d_dev.register_for_monitoring()
                if new_type in dict(Device.DeviceType.choices) and new_type != d_dev.device_type:
                    old_t = d_dev.device_type
                    d_dev.device_type = new_type
                    d_dev.type_manually_set = True
                    d_dev.confidence_score = 100
                    d_dev.identification_status = DiscoveredDevice.IdentificationStatus.MANUAL
                    d_dev.classification_reason = f"Manually classified by {request.user.username}"
                    NetworkChangeEvent.objects.create(
                        discovered_device=d_dev,
                        event_type=NetworkChangeEvent.EventType.TYPE_CHANGED,
                        severity=NetworkChangeEvent.Severity.INFO,
                        previous_value=old_t,
                        new_value=new_type,
                        description=f"Operator {request.user.username} manually updated device type for {d_dev.ip_address} from '{old_t}' to '{new_type}'.",
                    )
                d_dev.save()
                _log_audit(request.user, "update_discovered_device", "DiscoveredDevice", d_dev.ip_address, f"hostname={d_dev.hostname}, trust={d_dev.trust_status}, type={d_dev.device_type}", request)
                messages.success(request, f"Updated inventory record for {d_dev.ip_address}.")

        return redirect("devices:discovery")


# ─── REST API Views & ViewSets ────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def discovery_interfaces_api(request):
    """
    GET /api/discovery/interfaces/
    Returns all detected host network interfaces, IPv4 addresses, subnet masks,
    default gateways, MAC addresses, and calculated CIDR ranges.
    """
    include_loopback = request.query_params.get("include_loopback", "false").lower() in ("true", "1")
    active_only = request.query_params.get("active_only", "false").lower() in ("true", "1")
    interfaces = NetworkInterfaceDetector.detect_interfaces(
        include_loopback=include_loopback,
        active_only=active_only,
    )
    return Response({
        "count": len(interfaces),
        "primary_interface": interfaces[0].to_dict() if interfaces else None,
        "interfaces": [iface.to_dict() for iface in interfaces],
    })


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def validate_cidr_api(request):
    """
    POST /api/discovery/validate-cidr/
    Validates a CIDR or IP/mask against VIGIL's authorized RFC1918 scan scope.
    """
    cidr = request.data.get("cidr", "")
    is_valid, message, info = NetworkInterfaceDetector.validate_authorized_cidr(cidr)
    if not is_valid:
        return Response({"valid": False, "error": message}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"valid": True, "message": message, "network": info}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated, IsOperatorOrReadOnly])
def start_discovery_scan_api(request):
    """
    POST /api/discovery/scans/start/
    Validates target CIDR, creates a DiscoveryScan, and dispatches the scan task.
    Supports `run_async: true` to run non-blockingly in a background thread for live UI polling.
    """
    cidr = request.data.get("target_cidr") or request.data.get("cidr") or ""
    iface_name = request.data.get("interface_name", "")
    host_ips = request.data.get("host_ips")
    run_async = bool(request.data.get("run_async", False))

    is_valid, message, info = NetworkInterfaceDetector.validate_authorized_cidr(cidr)
    if not is_valid or not info:
        return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

    scan = DiscoveryScan.objects.create(
        interface_name=iface_name,
        target_cidr=info["network_cidr"],
        status=DiscoveryScan.Status.RUNNING if run_async else DiscoveryScan.Status.PENDING,
        progress_pct=5 if run_async else 0,
        started_by=request.user,
    )
    _log_audit(request.user, "api_start_discovery_scan", "DiscoveryScan", scan.target_cidr, f"Interface: {iface_name}", request)

    if run_async:
        launch_discovery_scan_background(scan.id, host_ips_override=host_ips)
    else:
        from monitoring.tasks import task_run_network_discovery
        try:
            task_run_network_discovery.delay(scan.id, host_ips_override=host_ips)
        except Exception:
            execute_discovery_scan_sync(scan, host_ips_override=host_ips)
        scan.refresh_from_db()

    return Response(DiscoveryScanSerializer(scan).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated, IsOperatorOrReadOnly])
def stop_discovery_scan_api(request, pk: int):
    """POST /api/discovery/scans/<pk>/stop/"""
    scan = get_object_or_404(DiscoveryScan, pk=pk)
    ACTIVE_SCAN_STOP_FLAGS.add(scan.id)
    cache.set(f"vigil:scan_stop:{scan.id}", True, timeout=120)
    scan.status = DiscoveryScan.Status.STOPPED
    scan.completed_at = timezone.now()
    scan.save(update_fields=["status", "completed_at"])
    _log_audit(request.user, "api_stop_discovery_scan", "DiscoveryScan", scan.target_cidr, "", request)
    return Response(DiscoveryScanSerializer(scan).data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def discovery_scan_status_api(request, pk: int):
    """GET /api/discovery/scans/<pk>/status/"""
    scan = get_object_or_404(DiscoveryScan, pk=pk)
    return Response(DiscoveryScanSerializer(scan).data, status=status.HTTP_200_OK)


class DiscoveredDeviceViewSet(viewsets.ModelViewSet):
    """
    REST API for managing discovered network inventory, updating trust status
    or manual device classification, and promoting devices to continuous monitoring.
    """
    queryset = DiscoveredDevice.objects.select_related("monitored_device", "last_scan").order_by("-last_discovered_at")
    serializer_class = DiscoveredDeviceSerializer
    permission_classes = [permissions.IsAuthenticated, IsOperatorOrReadOnly]

    def get_queryset(self):
        qs = super().get_queryset()
        trust = self.request.query_params.get("trust_status")
        dev_type = self.request.query_params.get("device_type")
        reachable = self.request.query_params.get("is_reachable")
        q = self.request.query_params.get("q", "").strip()

        if trust:
            qs = qs.filter(trust_status=trust)
        if dev_type:
            qs = qs.filter(device_type=dev_type)
        if reachable is not None:
            qs = qs.filter(is_reachable=reachable.lower() in ("true", "1"))
        if q:
            qs = qs.filter(
                Q(ip_address__icontains=q)
                | Q(mac_address__icontains=q)
                | Q(hostname__icontains=q)
                | Q(manufacturer__icontains=q)
            )
        return qs

    @action(detail=False, methods=["post"], url_path="register")
    def register_for_monitoring(self, request):
        """
        POST /api/discovery/devices/register/
        Body: {"ids": [1, 2, 3]} or {"register_all": true}
        Registers selected discovered devices into monitored Device records without duplicates.
        """
        ids = request.data.get("ids", [])
        register_all = bool(request.data.get("register_all", False))

        if register_all:
            targets = DiscoveredDevice.objects.exclude(trust_status=DiscoveredDevice.TrustStatus.IGNORED)
        else:
            targets = DiscoveredDevice.objects.filter(id__in=ids)

        registered_devices = []
        for d_dev in targets:
            mon_dev = d_dev.register_for_monitoring()
            registered_devices.append({
                "discovered_id": d_dev.id,
                "monitored_device_id": mon_dev.id,
                "name": mon_dev.name,
                "ip_address": mon_dev.ip_address,
            })

        _log_audit(
            request.user,
            "api_register_discovered_devices",
            "DiscoveredDevice",
            f"{len(registered_devices)} devices",
            "",
            request,
        )
        return Response({
            "registered_count": len(registered_devices),
            "devices": registered_devices,
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="classify")
    def classify(self, request, pk=None):
        """
        POST /api/discovery/devices/<pk>/classify/
        Allows an operator to manually set hostname, trust_status, and/or device_type.
        """
        from devices.hostname_resolver import HostnameResolver

        d_dev = self.get_object()
        new_trust = request.data.get("trust_status")
        new_type = request.data.get("device_type")
        new_hostname = request.data.get("hostname")

        if new_hostname is not None:
            cleaned_hn = str(new_hostname).strip()
            if cleaned_hn:
                if not HostnameResolver.is_valid_hostname(cleaned_hn, ip_address=d_dev.ip_address):
                    return Response(
                        {"error": f"Invalid hostname '{cleaned_hn}'. Never assign an IP address as a hostname."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                old_hn = d_dev.hostname
                d_dev.hostname = cleaned_hn
                d_dev.hostname_source = DiscoveredDevice.HostnameSource.MANUAL
                d_dev.hostname_manually_set = True
                d_dev.last_hostname_resolved_at = timezone.now()
                dh = dict(d_dev.discovered_hostnames or {})
                dh["manual"] = cleaned_hn
                d_dev.discovered_hostnames = dh
                if old_hn and old_hn != cleaned_hn:
                    NetworkChangeEvent.objects.create(
                        discovered_device=d_dev,
                        event_type=NetworkChangeEvent.EventType.HOSTNAME_CHANGED,
                        severity=NetworkChangeEvent.Severity.INFO,
                        previous_value=old_hn,
                        new_value=cleaned_hn,
                        description=f"Operator {request.user.username} manually assigned hostname '{cleaned_hn}' to {d_dev.ip_address}.",
                    )

        if new_trust and new_trust in dict(DiscoveredDevice.TrustStatus.choices):
            d_dev.trust_status = new_trust
            if new_trust == DiscoveredDevice.TrustStatus.MONITORED:
                d_dev.register_for_monitoring()

        if new_type and new_type in dict(Device.DeviceType.choices) and new_type != d_dev.device_type:
            old_type = d_dev.device_type
            d_dev.device_type = new_type
            d_dev.type_manually_set = True
            d_dev.confidence_score = 100
            d_dev.identification_status = DiscoveredDevice.IdentificationStatus.MANUAL
            d_dev.classification_reason = f"Manually classified by {request.user.username}"
            NetworkChangeEvent.objects.create(
                discovered_device=d_dev,
                event_type=NetworkChangeEvent.EventType.TYPE_CHANGED,
                severity=NetworkChangeEvent.Severity.INFO,
                previous_value=old_type,
                new_value=new_type,
                description=f"Operator {request.user.username} changed device type for {d_dev.ip_address} from '{old_type}' to '{new_type}'.",
            )

        d_dev.save()
        _log_audit(request.user, "api_classify_discovered_device", "DiscoveredDevice", d_dev.ip_address, f"hostname={d_dev.hostname}, trust={d_dev.trust_status}, type={d_dev.device_type}", request)
        return Response(DiscoveredDeviceSerializer(d_dev).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="refresh-identification")
    def refresh_identification(self, request, pk=None):
        """
        POST /api/discovery/devices/<pk>/refresh-identification/
        Retries multi-method hostname resolution and IEEE OUI vendor identification
        for a single discovered device without requiring a full network scan.
        """
        from devices.discovery import NetworkDiscoveryEngine

        d_dev = self.get_object()
        probe_net = bool(request.data.get("probe_network", True))
        NetworkDiscoveryEngine.refresh_single_device_identification(d_dev, probe_network=probe_net)
        d_dev.refresh_from_db()
        _log_audit(request.user, "api_refresh_identification", "DiscoveredDevice", d_dev.ip_address, "", request)
        return Response(DiscoveredDeviceSerializer(d_dev).data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="refresh-all")
    def refresh_all_identifications(self, request):
        """
        POST /api/discovery/devices/refresh-all/
        Retries hostname & IEEE OUI vendor identification across selected or all discovered devices.
        """
        from devices.discovery import NetworkDiscoveryEngine
        from concurrent.futures import ThreadPoolExecutor

        ids = request.data.get("ids")
        probe_net = bool(request.data.get("probe_network", True))
        if ids:
            targets = list(DiscoveredDevice.objects.filter(id__in=ids))
        else:
            targets = list(DiscoveredDevice.objects.all()[:100])

        def _refresh_one(dev_obj):
            from django.db import close_old_connections
            close_old_connections()
            return NetworkDiscoveryEngine.refresh_single_device_identification(dev_obj, probe_network=probe_net)

        if targets:
            with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
                list(pool.map(_refresh_one, targets))

        _log_audit(request.user, "api_refresh_all_identifications", "DiscoveredDevice", f"{len(targets)} devices", "", request)
        return Response({"refreshed_count": len(targets)}, status=status.HTTP_200_OK)


class NetworkChangeEventViewSet(viewsets.ReadOnlyModelViewSet):
    """REST API for inspecting and acknowledging network inventory change events."""
    queryset = NetworkChangeEvent.objects.select_related("discovered_device").order_by("-created_at")
    serializer_class = NetworkChangeEventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        event_type = self.request.query_params.get("event_type")
        ack = self.request.query_params.get("is_acknowledged")
        if event_type:
            qs = qs.filter(event_type=event_type)
        if ack is not None:
            qs = qs.filter(is_acknowledged=ack.lower() in ("true", "1"))
        return qs

    @action(detail=True, methods=["post"], url_path="acknowledge", permission_classes=[permissions.IsAuthenticated, IsOperatorOrReadOnly])
    def acknowledge(self, request, pk=None):
        ev = self.get_object()
        ev.is_acknowledged = True
        ev.save(update_fields=["is_acknowledged"])
        return Response(NetworkChangeEventSerializer(ev).data, status=status.HTTP_200_OK)
