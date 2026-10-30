from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    LoginView,
    LogoutView,
    RegisterView,
    ProfileView,
    UserListView,
    UserEditView,
    UserViewSet,
)

app_name = "accounts"

# REST API with distinct basename to avoid colliding with template view names
router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user-api")

urlpatterns = [
    # Template-based auth views
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("register/", RegisterView.as_view(), name="register"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("users/<int:pk>/edit/", UserEditView.as_view(), name="user-edit"),

    # REST API
    path("api/", include(router.urls)),
]
