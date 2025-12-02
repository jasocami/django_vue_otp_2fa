import logging

from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, extend_schema_view, inline_serializer
from rest_framework import viewsets, serializers
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.accounts.serializers import UserSerializer
from apps.generic.api.api_permissions import IsOTPVerified

logger = logging.getLogger(__name__)
UserModel = get_user_model()


@extend_schema(tags=['Accounts'])
@extend_schema_view(
    list=extend_schema(description='List of users', summary='List of users', responses={200: UserSerializer(many=True)}),
    retrieve=extend_schema(description='Get a single user', summary='Retrieve user', responses={200: UserSerializer}),
    me=extend_schema(
        description='Get me own user data', summary='Retrieve my own user data', responses={200: UserSerializer}),
)
class UserViewSet(viewsets.ModelViewSet):
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer
    pagination_class = None

    # def get_permissions(self):
    #     if self.action != 'me':
    #         return [IsOTPVerified()]
    #     return super().get_permissions()

    @action(detail=False, methods=['GET'], url_path='me')
    def me(self, request, *args, **kwargs):
        """ Get the information for my user """
        return Response(self.get_serializer(request.user).data)

    @extend_schema(
        request=None,
        summary='Blocked',
        responses={
            200: inline_serializer(name='BlockedResponse', fields={'success': serializers.BooleanField()}),
            400: None,
        },
    )
    @action(detail=False, methods=['GET'], url_path='blocked')
    def blocked(self, request, *args, **kwargs):
        """ URL to test if OTP code is validated. Only accessible for users that passed 2FA test """
        return Response({'success': True})
