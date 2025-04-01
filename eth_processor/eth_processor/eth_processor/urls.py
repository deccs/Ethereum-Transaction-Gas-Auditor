from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView

urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "api/", include("transactions.urls")
    ),  # Ensure this line exists and points to your app's urls
    path("", TemplateView.as_view(template_name="index.html")),
    path(".+", TemplateView.as_view(template_name="index.html")),  # Adjusted catch-all
]
