from django.urls import path
from . import views

urlpatterns = [
    path("transaction/", views.process_transaction, name="process_transaction"),
]
