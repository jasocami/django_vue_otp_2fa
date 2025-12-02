from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from constance import config as constance_config

from apps.accounts.constants import OTPChoices
from apps.accounts.models import OTP

UserModel = get_user_model()


class IsOTPVerified(IsAuthenticated):
    """ Allows access only to authenticated admin users. """

    def has_permission(self, request, view):
        is_auth = super().has_permission(request, view)
        if not constance_config.IS_TWO_FACTOR_AUTH_ACTIVE:
            return is_auth
        try:
            # Check latest OTP code verification
            otp_instance = request.user.otps.get(otp_type=OTPChoices.LOGIN)
            return bool(is_auth and otp_instance.is_verified)
        except OTP.DoesNotExist:
            return False


class IsAuthenticatedAndIsStaffUser(IsAdminUser):

    def has_permission(self, request, view):
        is_staff = super().has_permission(request, view)
        return bool(is_staff and request.user.is_authenticated)
