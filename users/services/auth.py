from rest_framework_simplejwt.tokens import RefreshToken
import time
from redis import Redis


r = Redis(host="localhost", port=6379, db=0)


def generate_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    jti = str(refresh["jti"])
    exp_timestamp = refresh["exp"]
    ttl = int(exp_timestamp - time.time())

    r.setex(f"refresh:{jti}", ttl, str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "jti": jti,
        "ttl": ttl,
    }


def validate_refresh_token(refresh_token_string):
    try:
        token = RefreshToken(refresh_token_string)
    except Exception:
        return None
    
    jti = str(token['jti'])
    user_id = str(token['user_id'])

    user_id_bytes = r.get(f"refresh:{jti}")
    if not user_id_bytes:
        return None
    
    redis_user_id = user_id_bytes.decode()
    if user_id != redis_user_id:
        return None
    
    r.delete(f"refresh:{jti}")

    return user_id


def invalidate_refresh_token(refresh_token_string):
    try:
        refresh = RefreshToken(refresh_token_string)
    except Exception:
        return False
    
    jti = str(refresh['jti'])
    return r.delete(f"refresh:{jti}") > 0
