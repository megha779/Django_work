import re
import json
from rest_framework import status
from django.http import JsonResponse
from django.contrib.auth import logout
from django.contrib.auth.models import User
from rest_framework.response import Response
from django.contrib.auth import authenticate
from api.serializers import UserProfileSerializer
from rest_framework.authtoken.models import Token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from .serializers import AdminUserListSerializer

@api_view(['POST'])
@authentication_classes([])  # Disable authentication for registration
@permission_classes([])  # Disable permission checks for registration
def register_view(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")
    is_admin = request.data.get("is_admin", False)

    if User.objects.filter(username=username).exists():
        return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(email=email).exists():
        return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

    if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password):
        return Response({"error": "Password must be at least 8 characters long, contain at least one uppercase letter and one number."}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)

    if is_admin:
        user.is_staff = True
        user.is_superuser = True
        user.save()

    token = Token.objects.create(user=user)

    return Response({
        "message": "User registered successfully",
        "token": token.key
    }, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login_view(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)

    if user is not None:
        return Response({
            "message":"Logged in successfully"})
    else:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    return Response({
        "username":user.username,
        "email":user.email
    },status=status.HTTP_200_OK)

@api_view(['GET','PUT'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_profile(request):
    try:
        user = request.user 
        if request.method == 'GET':
            serializer = UserProfileSerializer(user)
            return Response(serializer.data)
        if request.method == 'PUT':
            serializer = UserProfileSerializer(user, data=request.data)
            if serializer.is_valid():
             serializer.save()
             return Response(serializer.data)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({"error":"User not found"})
    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        user = request.user

        if user.check_password(old_password):
            user.set_password(new_password)
            user.save()
            return JsonResponse({"message": "Password updated successfully"})
        else:
            return JsonResponse({"error": "Old password is incorrect"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@api_view(['POST'])
def logout_view(request):
    # Checking if the user is authenticated
    if request.user.is_authenticated:   
        # Calling Django's logout function to clear the session
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "User is not logged in"}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def current_user(request):
    user = request.user
    return Response({
        "username": user.username,
        "email": user.email
    }, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def user_profile_view(request):
    try:
        user = request.user

        if request.method == 'GET':
            serializer = UserProfileSerializer(user)
            return Response(serializer.data)

        elif request.method == 'PUT':
            serializer = UserProfileSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            user.delete()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAdminUser])
def admin_user_list(request):
    users = User.objects.all()
    user_data = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser
        }
        for user in users
    ]
    return Response(user_data, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([IsAdminUser])  
def admin_delete_user(request, user_id):
    try:
        user = User.objects.get(id=user_id) 
        user.delete()
        return Response({"message": "User deleted successfully"}, status=204)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

@api_view(['GET', 'PUT'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def admin_user_detail_update(request, user_id):
    try:
        user = User.objects.get(id=user_id)

        if request.method == 'GET':
            serializer = AdminUserListSerializer(user)
            return Response(serializer.data)

        elif request.method == 'PUT':
            serializer = AdminUserListSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)

    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)
