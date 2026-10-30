from rest_framework import viewsets, permissions
from .models import NetworkConnection
from .serializers import NetworkConnectionSerializer


class NetworkConnectionViewSet(viewsets.ModelViewSet):
    """
    API for retrieving and managing network connections and topology nodes.
    """
    queryset = NetworkConnection.objects.all().select_related(
        "source_device",
        "destination_device",
        "source_interface",
        "destination_interface",
    )
    serializer_class = NetworkConnectionSerializer
    permission_classes = [permissions.IsAuthenticated]
