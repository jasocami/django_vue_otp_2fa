from rest_framework_simplejwt.authentication import AuthUser


def user_authentication_rule(user: AuthUser) -> bool:
    return user is not None and user.is_active is True
