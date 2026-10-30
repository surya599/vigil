from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import UserProfile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Ensure every Django User has an associated UserProfile.
    Superusers automatically receive the ADMINISTRATOR role.
    """
    if created:
        role = (
            UserProfile.Role.ADMINISTRATOR
            if instance.is_superuser
            else UserProfile.Role.OPERATOR
        )
        UserProfile.objects.create(user=instance, role=role)
    else:
        # Save profile if it exists
        if hasattr(instance, "profile"):
            if instance.is_superuser and instance.profile.role != UserProfile.Role.ADMINISTRATOR:
                instance.profile.role = UserProfile.Role.ADMINISTRATOR
            instance.profile.save()
        else:
            role = (
                UserProfile.Role.ADMINISTRATOR
                if instance.is_superuser
                else UserProfile.Role.OPERATOR
            )
            UserProfile.objects.create(user=instance, role=role)
