from django.db import models
from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """
    Custom permission to grant access to only admin users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.groups.filter(name='Admin').exists()

class IsManagerUser(BasePermission):
    """
    Custom permission to grant access to only manager users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.groups.filter(name='Manager').exists()

class IsRegularUser(BasePermission):
    """
    Custom permission to grant access to regular users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.groups.filter(name='User').exists()
    

