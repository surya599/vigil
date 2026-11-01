from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages


class AdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Restrict view access to users with the Administrator role."""

    def test_func(self):
        return hasattr(self.request.user, "profile") and self.request.user.profile.is_admin

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "You need Administrator privileges to access this page.")
        return redirect("dashboard:overview")


class OperatorRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Restrict view access to Operators and Administrators."""

    def test_func(self):
        return hasattr(self.request.user, "profile") and self.request.user.profile.is_operator

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "You need Operator privileges to access this page.")
        return redirect("dashboard:overview")


def admin_required(view_func):
    """Function-based view decorator for Administrator-only access."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        if not (hasattr(request.user, "profile") and request.user.profile.is_admin):
            messages.error(request, "You need Administrator privileges to access this page.")
            return redirect("dashboard:overview")
        return view_func(request, *args, **kwargs)
    return _wrapped


def operator_required(view_func):
    """Function-based view decorator for Operator-or-Admin access."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        if not (hasattr(request.user, "profile") and request.user.profile.is_operator):
            messages.error(request, "You need Operator privileges to access this page.")
            return redirect("dashboard:overview")
        return view_func(request, *args, **kwargs)
    return _wrapped


class IsOperatorOrReadOnly:
    """
    DRF permission class allowing read-only access (GET, HEAD, OPTIONS) to any
    authenticated user, and write access (POST, PUT, PATCH, DELETE) only to
    Operators and Administrators.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        return bool(
            request.user.is_superuser
            or (hasattr(request.user, "profile") and request.user.profile.is_operator)
        )

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)
