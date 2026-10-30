from django.urls import path
from .views import DashboardOverviewView, dashboard_stats

app_name = "dashboard"

urlpatterns = [
    path("", DashboardOverviewView.as_view(), name="overview"),
    path("stats/", dashboard_stats, name="stats"),
]
