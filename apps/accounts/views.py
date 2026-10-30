from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views import View
from django.views.generic import ListView
from rest_framework import viewsets, permissions

from .forms import NetPulseLoginForm, UserRegistrationForm, UserProfileUpdateForm
from .models import UserProfile
from .serializers import UserSerializer, UserProfileSerializer
from .permissions import AdminRequiredMixin

User = get_user_model()


# ─── Authentication Views ──────────────────────────────────────────────────────

class LoginView(View):
    """NOC login page with session-based authentication."""
    template_name = "accounts/login.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("dashboard:overview")
        form = NetPulseLoginForm(request)
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = NetPulseLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Extend session lifetime when "Remember Me" is checked
            if not form.cleaned_data.get("remember_me"):
                request.session.set_expiry(0)  # Expire on browser close
            else:
                request.session.set_expiry(60 * 60 * 24 * 14)  # 14 days
            messages.success(request, f"Welcome back, {user.get_full_name() or user.username}!")
            next_url = request.GET.get("next", "dashboard:overview")
            return redirect(next_url)
        return render(request, self.template_name, {"form": form})


class LogoutView(View):
    """Logs out the current user and clears the session."""

    def post(self, request):
        logout(request)
        messages.info(request, "You have been logged out of NetPulse.")
        return redirect("accounts:login")

    def get(self, request):
        # Allow GET for simple link-based logout
        logout(request)
        return redirect("accounts:login")


class RegisterView(AdminRequiredMixin, View):
    """Create new NOC user accounts. Restricted to Administrators."""
    template_name = "accounts/register.html"

    def get(self, request):
        form = UserRegistrationForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(
                request,
                f"Account created successfully for {user.username} with role {user.profile.get_role_display()}.",
            )
            return redirect("accounts:user-list")
        return render(request, self.template_name, {"form": form})


# ─── Profile Views ─────────────────────────────────────────────────────────────

class ProfileView(LoginRequiredMixin, View):
    """View and update the current user's own NOC profile."""
    template_name = "accounts/profile.html"
    login_url = "accounts:login"

    def get(self, request):
        form = UserProfileUpdateForm(instance=request.user.profile, user=request.user)
        return render(request, self.template_name, {"form": form, "profile": request.user.profile})

    def post(self, request):
        form = UserProfileUpdateForm(
            request.POST, instance=request.user.profile, user=request.user
        )
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect("accounts:profile")
        return render(request, self.template_name, {"form": form, "profile": request.user.profile})


class UserListView(AdminRequiredMixin, ListView):
    """List all registered NOC users. Administrator only."""
    model = User
    template_name = "accounts/user_list.html"
    context_object_name = "users"
    paginate_by = 25

    def get_queryset(self):
        return User.objects.select_related("profile").order_by("username")


class UserEditView(AdminRequiredMixin, View):
    """Edit role and profile of any registered user. Administrator only."""
    template_name = "accounts/user_edit.html"

    def get(self, request, pk):
        target_user = get_object_or_404(User, pk=pk)
        form = UserProfileUpdateForm(instance=target_user.profile, user=target_user)
        # Allow role editing for admins
        role_choices = UserProfile.Role.choices
        return render(request, self.template_name, {
            "form": form,
            "target_user": target_user,
            "role_choices": role_choices,
        })

    def post(self, request, pk):
        target_user = get_object_or_404(User, pk=pk)
        form = UserProfileUpdateForm(request.POST, instance=target_user.profile, user=target_user)
        if form.is_valid():
            # Allow admin to update role
            new_role = request.POST.get("role")
            if new_role and new_role in [r[0] for r in UserProfile.Role.choices]:
                target_user.profile.role = new_role
            form.save()
            messages.success(request, f"Profile for {target_user.username} updated.")
            return redirect("accounts:user-list")
        return render(request, self.template_name, {
            "form": form,
            "target_user": target_user,
            "role_choices": UserProfile.Role.choices,
        })


# ─── REST API ViewSets ──────────────────────────────────────────────────────────

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for registered users — read-only, requires authentication."""
    queryset = User.objects.all().select_related("profile").order_by("id")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
