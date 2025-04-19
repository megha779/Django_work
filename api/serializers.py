from rest_framework import serializers
from django.contrib.auth.models import User

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff', 'is_superuser']

class AdminUserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff', 'is_superuser']
