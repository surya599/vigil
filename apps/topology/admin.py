from django.contrib import admin
from .models import NetworkConnection


@admin.register(NetworkConnection)
class NetworkConnectionAdmin(admin.ModelAdmin):
    list_display = (
        "source_device",
        "destination_device",
        "connection_type",
        "link_speed",
        "status",
        "is_discovered",
        "updated_at",
    )
    list_filter = ("connection_type", "status", "is_discovered")
    search_fields = ("source_device__name", "destination_device__name", "description")
