from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.exceptions import AuthenticationFailed
from .services.users import get_user_by_id


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header =  request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        access_token_string = auth_header.split(" ")[1]
        
        try:
            token = AccessToken(access_token_string)
        except Exception:
            raise AuthenticationFailed("Invalid access token")
        
        user_id = str(token["user_id"])
        user = get_user_by_id(user_id)

        if not user:
            raise AuthenticationFailed("User not found")
        
        return (user, token)
