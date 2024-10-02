from django.urls import path
from .api import *


urlpatterns = [
    path('cust/',CustomerListCreateView.as_view()),
    path('cust/<pk>/',CustomerDetailView.as_view()),
]