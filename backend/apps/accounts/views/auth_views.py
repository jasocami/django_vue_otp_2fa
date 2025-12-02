import logging

from django.conf import settings
from django.contrib.auth import logout as django_logout
from drf_spectacular.utils import extend_schema, inline_serializer, OpenApiExample
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

from apps.accounts.serializers import UserSerializer, ObtainUserTokenSerializer
from apps.generic.api.api_exceptions import LogoutNotPossibleException
from apps.generic.docstrings import override_docstring

logger = logging.getLogger(__name__)


@extend_schema(
    request=ObtainUserTokenSerializer,
    tags=['Auth'],
    auth=[],
    summary='Login',
    examples=[
        OpenApiExample(
            name='Simple login example',
            summary='Simple login example',
            value={'email': 'example@domain.com', 'password': '123asd'},
            request_only=True,
        ),
    ],
    responses={
        200: inline_serializer(
            name='LoginResponse',
            fields={
                'tokens': inline_serializer(
                    name='tokensResponse',
                    fields={'access': serializers.CharField(), 'refresh': serializers.CharField()}
                ),
                'user': UserSerializer()
            }
        ),
        400: None
    },
)
@override_docstring(errors=[
    'AuthenticationFailedException', 'NoActiveAccountException', 'PasswordExpiredException', 'NotFoundException'
])
class LoginView(TokenObtainPairView):
    """
    Login

    Possible errors:

    {errors}
    """
    pass


@extend_schema(
    request=inline_serializer(
        name='LogoutInlineSerializer',
        fields={'refresh': serializers.CharField(required=True, help_text='Token used to refresh access token')}
    ),
    tags=['Auth'],
    summary='Logout',
    description='Logout',
    responses={205: None, 400: None},
)
@override_docstring(errors=['LogoutNotPossibleException'])
class LogoutView(APIView):
    """
    Calls Django logout method and delete the Token object assigned to the current User object.
    black list refresh token.

    Possible errors:

    {errors}
    """
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            if getattr(settings, 'REST_SESSION_LOGIN', True):
                django_logout(request)
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            logger.error(str(e))

        raise LogoutNotPossibleException()


@extend_schema(
    request=TokenRefreshSerializer,
    tags=['Auth'],
    summary='Token refresh',
    description='Token refresh',
    responses={
        200: inline_serializer(name='TokenRefreshResponse', fields={'access': serializers.CharField()}),
        400: None
    },
)
class CustomTokenRefreshView(TokenRefreshView):
    pass