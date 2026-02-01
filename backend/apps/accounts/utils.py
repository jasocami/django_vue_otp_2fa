from datetime import timedelta

from django.utils import timezone
from constance import config as constance_config


def get_otp_expire_datetime():
    return timezone.now() + timedelta(minutes=constance_config.OTP_CODE_EXPIRATION)
