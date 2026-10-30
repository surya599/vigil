from django import forms
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from .models import Device


class DeviceForm(forms.ModelForm):
    """
    Full device creation and editing form.
    SNMP credentials are optional fields rendered only when snmp_enabled is checked.
    """

    class Meta:
        model = Device
        fields = (
            "name",
            "ip_address",
            "mac_address",
            "device_type",
            "location",
            "description",
            "monitoring_enabled",
            "polling_interval",
            # SNMP
            "snmp_enabled",
            "snmp_version",
            "snmp_port",
            "snmp_community",
            "snmp_v3_user",
            "snmp_v3_auth_protocol",
            "snmp_v3_auth_key",
            "snmp_v3_priv_protocol",
            "snmp_v3_priv_key",
        )
        widgets = {
            "name": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. Core-Router-01",
            }),
            "ip_address": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. 192.168.1.1",
                "id": "id_ip_address",
            }),
            "mac_address": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. AA:BB:CC:DD:EE:FF (optional)",
            }),
            "device_type": forms.Select(attrs={"class": "form-select"}),
            "location": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. Data Center Rack A-01",
            }),
            "description": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Optional device notes…",
            }),
            "monitoring_enabled": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "polling_interval": forms.NumberInput(attrs={
                "class": "form-control",
                "min": 5,
                "max": 3600,
            }),
            "snmp_enabled": forms.CheckboxInput(attrs={
                "class": "form-check-input",
                "id": "id_snmp_enabled",
            }),
            "snmp_version": forms.Select(attrs={"class": "form-select"}),
            "snmp_port": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 65535}),
            "snmp_community": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Community string (SNMPv2c)",
                "autocomplete": "off",
            }),
            "snmp_v3_user": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "SNMPv3 Username",
                "autocomplete": "off",
            }),
            "snmp_v3_auth_protocol": forms.Select(attrs={"class": "form-select"}),
            "snmp_v3_auth_key": forms.PasswordInput(attrs={
                "class": "form-control",
                "placeholder": "Auth passphrase",
                "autocomplete": "new-password",
            }),
            "snmp_v3_priv_protocol": forms.Select(attrs={"class": "form-select"}),
            "snmp_v3_priv_key": forms.PasswordInput(attrs={
                "class": "form-control",
                "placeholder": "Privacy passphrase",
                "autocomplete": "new-password",
            }),
        }

    def clean_ip_address(self):
        ip = self.cleaned_data.get("ip_address", "").strip()
        try:
            validate_ipv46_address(ip)
        except ValidationError:
            raise forms.ValidationError(
                f"'{ip}' is not a valid IPv4 or IPv6 address."
            )
        # Check uniqueness excluding current instance on updates
        qs = Device.objects.filter(ip_address=ip)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError(
                f"A device with IP address {ip} is already registered."
            )
        return ip

    def clean(self):
        cleaned = super().clean()
        snmp_enabled = cleaned.get("snmp_enabled", False)
        snmp_version = cleaned.get("snmp_version", "v2c")

        if snmp_enabled and snmp_version == Device.SNMPVersion.V3:
            if not cleaned.get("snmp_v3_user"):
                self.add_error("snmp_v3_user", "SNMPv3 username is required when SNMPv3 is enabled.")
            if not cleaned.get("snmp_v3_auth_key"):
                self.add_error("snmp_v3_auth_key", "SNMPv3 authentication passphrase is required.")
        return cleaned
