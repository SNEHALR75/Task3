
from .serializers import CustomerSerializer
from rest_framework.response import Response
from .models import Customer
from rest_framework import generics
from rest_framework_simplejwt.authentication import JWTAuthentication   
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly
from account.autheticate import CustomAuthentication
from django.core.mail import send_mail
from django.conf import settings

import logging
logger = logging.getLogger(__name__)

class CustomerListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticatedOrReadOnly,]
    authentication_classes = [CustomAuthentication,]
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer


    def perform_create(self, serializer):
        serializer.save()
        logger.info("New Data added")

        send_mail(
                subject = "Notification:",
                message = "new record added....",
                from_email = settings.EMAIL_HOST_USER ,
                recipient_list = [self.request.user.email]
                )



    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        logger.info(f"Listed objects: {response.data}")
        return response


class CustomerDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated,]
    authentication_classes = [CustomAuthentication,]
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer

    

    def get_object(self):
        obj = super().get_object()
        logger.info(f"Retrieved object: {obj}")
        return obj


    def perform_update(self, serializer):
        serializer.save()
        logger.info(f"Updated object: {serializer.data}")
        send_mail(
                subject = "Notification:",
                message = "new record Updated....",
                from_email = settings.EMAIL_HOST_USER ,
                recipient_list = [self.request.user.email]
                )


    def perform_destroy(self, instance):
        logger.info(f"Deleted object: {instance}")
        instance.delete()
        send_mail(
                subject = "Notification:",
                message = "new record Deleted....",
                from_email = settings.EMAIL_HOST_USER ,
                recipient_list = [self.request.user.email]
                )


