import logging
from typing import Dict, Any

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings

from apps.generic.api.api_exceptions import AuthenticationFailedException, NoActiveAccountException, \
    OTPCodeInvalidExpiredException
from .constants import OTPChoices
from .models import OTP, TrustedDevice
from ..generic.communications import Communication
from ..generic.serializer_fields import custom_datetime_field
from constance import config as constance_config

UserModel = get_user_model()
logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """ Extended info for a user model """

    date_joined = custom_datetime_field()
    otp_verified = serializers.SerializerMethodField()

    class Meta:
        model = UserModel
        exclude = ('password', 'groups', 'user_permissions', 'last_login')

    def get_otp_verified(self, obj):
        return obj.has_otp_verified


class ObtainUserTokenSerializer(TokenObtainPairSerializer):
    """ Overridden serializer for login """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            "password": attrs["password"],
        }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if not self.user:
            raise AuthenticationFailedException()

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise NoActiveAccountException()

        data = {}

        # if self.user.expiration_date is None or self.user.expiration_date < date.today():
        #     # token = default_token_generator.make_token(self.user)
        #     # Communication().send_update_expired_password_email(self.user, constance_config.FRONTEND_URL, token)
        #     raise PasswordExpiredException()

        refresh = self.get_token(self.user)

        if constance_config.IS_TWO_FACTOR_AUTH_ACTIVE:
            # Check if device is already trusted (no OTP needed)
            request = self.context.get('request')
            if request and TrustedDevice.is_device_trusted(self.user, request):
                logger.info(f"Device is trusted for user {self.user.email}, skipping OTP")
                # Mark OTP as verified if exists
                OTP.objects.filter(user=self.user, otp_type=OTPChoices.LOGIN)\
                    .update(is_verified=True, is_active=False)
            else:
                otp_instance, _ = OTP.objects.get_or_create(
                    user=self.user,
                    otp_type=OTPChoices.LOGIN
                )
                otp_instance.generate_otp()
                logger.info(f"OTP generated for user {self.user.email}")

                try:
                    Communication().send_otp_email(
                        user=self.user,
                        otp_code=otp_instance.otp,
                        expiration_minutes=constance_config.OTP_CODE_EXPIRATION
                    )
                    logger.info(f"OTP email sent to {self.user.email}")
                except Exception as e:
                    logger.error(f"Failed to send OTP email to {self.user.email}: {e}")
                    # Continue login process even if email fails - user can resend OTP

        data['tokens'] = {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        data['user'] = UserSerializer(self.user).data

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class OTPSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6)

    def validate_otp_code(self, value):
        """
        Validates that the OTP contains only numeric characters and has the correct length.
        """
        if not value.isdigit() or len(value) != 6:
            raise OTPCodeInvalidExpiredException()
        return value

    def validate_otp_user(self, otp_instance):
        otp_code = self.validated_data['otp_code']
        if otp_instance.validate_otp_code(otp_code) and not otp_instance.is_expired():
            return True
        raise OTPCodeInvalidExpiredException()
