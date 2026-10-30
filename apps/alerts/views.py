from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Alert, AlertThreshold
from .serializers import AlertSerializer, AlertThresholdSerializer


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
