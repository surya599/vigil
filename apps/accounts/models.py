from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model


class UserProfile(models.Model):
    """
    Extends Django's user model with role-based access control and contact details.
    """

    class Role(models.TextChoices):
        ADMINISTRATOR = "admin", "Administrator"
        OPERATOR = "operator", "Operator"
        VIEWER = "viewer", "Viewer"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
        help_text="Underlying Django authentication user",
    )
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.OPERATOR,
        help_text="Role determining access permissions in NetPulse",
        db_index=True,
    )
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        help_text="Contact number for SMS or critical alerts",
    )
    department = models.CharField(
        max_length=100,
        blank=True,
        help_text="Department or team (e.g. NOC Operations, NetOps, DevOps)",
    )
    email_notifications = models.BooleanField(
        default=True,
        help_text="Whether to receive email notifications for critical incidents",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ["user__username"]

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    @property
    def is_admin(self) -> bool:
        return self.role == self.Role.ADMINISTRATOR or self.user.is_superuser

    @property
    def is_operator(self) -> bool:
        return self.role in (self.Role.OPERATOR, self.Role.ADMINISTRATOR) or self.user.is_superuser

    @property
    def can_manage_devices(self) -> bool:
        return self.is_operator

    @property
    def can_acknowledge_alerts(self) -> bool:
        return self.is_operator
