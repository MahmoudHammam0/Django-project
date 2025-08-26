from django.contrib.auth import authenticate
from ..models import User


def authenticate_user(request, username, password):
    return authenticate(request=request, username=username, password=password)


def get_user_by_id(user_id):
    return User.objects.filter(id=user_id).first()
