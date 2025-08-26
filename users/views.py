from .authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignupSerializer, UserResponseSerializer, LoginSerializer
from .models import User
from .services.users import authenticate_user, get_user_by_id
from .services.auth import (
    generate_tokens_for_user,
    validate_refresh_token,
    invalidate_refresh_token
)


class SignupView(APIView):
    def post(self, request):
        email = request.data.get("email")
        existing_user = User.objects.filter(email=email).first()
        if existing_user:
            return Response(
                {"status": "Email address already registerd"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_data = UserResponseSerializer(user).data
            return Response(
                {"status": "User signed up successfully!", "user": user_data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate_user(
            request=request,
            username=serializer.validated_data["email"],
            password=serializer.validated_data["password"]
        )
        if not user:
            return Response({
                "status": "Invalid email address or password"
                }, status=status.HTTP_401_UNAUTHORIZED)
        
        tokens = generate_tokens_for_user(user)
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        user_data = UserResponseSerializer(user).data

        response = Response({
            "status": "User logged in successfully",
            "user": user_data,
            "access_token": access_token,
            "token_type": "Bearer"
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Strict",
            max_age=7*24*60*60
        )

        return response
    

class RefreshView(APIView):
    def post(self, request):
        refresh_token_string = request.COOKIES.get("refresh_token")
        if not refresh_token_string:
            return Response({
                "status": "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED)

        user_id = validate_refresh_token(refresh_token_string)
        if not user_id:
            return Response({
                "status": "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED)

        user = get_user_by_id(user_id)
        if not user:
            return Response({
                "status": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)
        
        tokens = generate_tokens_for_user(user)
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        user_data = UserResponseSerializer(user).data

        response = Response({
            "status": "Tokens refreshed successfully",
            "user": user_data,
            "access_token": access_token,
            "token_type": "Bearer"
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Strict",
            max_age=7*24*60*60
        )

        return response
    

class LogoutView(APIView):
    def delete(self, request):
        refresh_token_string = request.COOKIES.get("refresh_token")
        if not refresh_token_string:
            return Response({
                "status": "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        invalidate_refresh_token(refresh_token_string)

        response = Response({
            "status": "User logged out successfully"
        }, status=status.HTTP_200_OK)

        response.delete_cookie("refresh_token")

        return response
    

class GetCurrentUser(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user =  request.user

        user_data = UserResponseSerializer(user).data

        return Response({
            "status": "User fetched successfully",
            "user": user_data
        }, status=status.HTTP_200_OK)
