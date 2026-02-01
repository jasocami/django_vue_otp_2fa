import base64
import hashlib
from datetime import timedelta

import pyotp
from constance import config as constance_config
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.accounts.constants import OTPChoices
from apps.accounts.managers import CustomUserManager
from apps.accounts.utils import get_otp_expire_datetime


class User(AbstractBaseUser, PermissionsMixin):
    """ Model for a user account """

    ANONYMIZE_EMAIL_DOMAIN = '@anonymize.com'

    email = models.EmailField(_('email address'), max_length=255, unique=True)
    first_name = models.CharField(_('first name'), max_length=100)
    last_name = models.CharField(_('last name'), max_length=100)
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email

    def get_full_name(self):
        """ Return the first_name plus the last_name, with a space in between. """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    @property
    def has_otp_verified(self) -> bool:
        if not constance_config.IS_TWO_FACTOR_AUTH_ACTIVE:
            return True
        try:
            otp = self.otps.get(otp_type=OTPChoices.LOGIN)
            return otp.is_verified
        except OTP.DoesNotExist:
            return False

    def anonymize(self):
        import uuid
        uid = str(uuid.uuid1())
        self.first_name = uid
        self.last_name = uid
        self.email = '%s%s' % (uid.replace('-', ''), self.ANONYMIZE_EMAIL_DOMAIN)
        self.is_active = False


def default_expires_at():
    """Default expiration time for OTP (4 minutes from now)"""
    return timezone.now() + timedelta(minutes=constance_config.OTP_CODE_EXPIRATION)


class OTP(models.Model):
    user = models.ForeignKey(User, related_name='otps', on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6, help_text='OTP generated code')
    otp_type = models.CharField(max_length=6, choices=OTPChoices.choices, default=OTPChoices.LOGIN)
    is_verified = models.BooleanField(default=False, help_text='The user has verified this code')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=default_expires_at)
    regenerated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'otp_type'], name='unique_together_user_otp_type'
            )
        ]

    def __str__(self):
        return f'User: {self.user} type: {self.otp_type}'

    def is_expired(self) -> bool:
        """Check if the OTP has expired"""
        return timezone.now() > self.expires_at

    def _generate_secret(self):
        email_hash = hashlib.sha256(self.user.email.encode()).digest()
        secret = base64.b32encode(email_hash).decode('utf-8').rstrip('=')
        return secret

    def generate_otp(self):
        """Generate a new OTP and update fields"""
        totp = pyotp.TOTP(self._generate_secret())
        self.otp_code = totp.now()
        self.is_active = True
        self.is_verified = False
        self.expires_at = timezone.now() + timedelta(minutes=constance_config.OTP_CODE_EXPIRATION)
        self.regenerated_at = timezone.now()
        self.save()

    def validate_otp(self, otp_input: str) -> bool:
        """Validate an OTP entered by the user"""
        if not self.is_active:
            return False
        if self.otp_code != otp_input:
            return False
        totp = pyotp.TOTP(self._generate_secret())
        # 8 windows of 30 sec = 4 minutes
        if totp.verify(otp_input, valid_window=8):
            self.is_verified = True
            self.is_active = False
            self.save()
            return True
        return False


def default_trusted_device_expires_at():
    """Default expiration time for TrustedDevice (24 hours from now)"""
    return timezone.now() + timedelta(hours=constance_config.TRUSTED_DEVICE_DURATION_HOURS)


class TrustedDevice(models.Model):
    """
    Model for trusted devices that don't require OTP verification.
    After successful OTP verification, the device is trusted for 24 hours.
    """
    user = models.ForeignKey('User', related_name="trusted_devices", on_delete=models.CASCADE)
    device_fingerprint = models.CharField(max_length=255, help_text="Hash of User-Agent + IP")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=default_trusted_device_expires_at)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'device_fingerprint']),
        ]

    def __str__(self):
        return f"TrustedDevice for {self.user.email} (expires: {self.expires_at})"

    def is_valid(self) -> bool:
        """Check if the trusted device is still valid"""
        return self.is_active and timezone.now() < self.expires_at

    @classmethod
    def create_fingerprint(cls, request) -> str:
        """Generate a device fingerprint from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip_address = cls.get_client_ip(request)
        fingerprint_string = f"{user_agent}:{ip_address}"
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()

    @staticmethod
    def get_client_ip(request) -> str:
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    @classmethod
    def is_device_trusted(cls, user, request) -> bool:
        """Check if the current device is trusted for the user"""
        fingerprint = cls.create_fingerprint(request)
        return cls.objects.filter(
            user=user,
            device_fingerprint=fingerprint,
            is_active=True,
            expires_at__gt=timezone.now()
        ).exists()

    @classmethod
    def trust_device(cls, user, request):
        """Create or update a trusted device entry"""
        fingerprint = cls.create_fingerprint(request)
        trusted_device, _ = cls.objects.update_or_create(
            user=user,
            device_fingerprint=fingerprint,
            defaults={
                'expires_at': timezone.now() + timedelta(hours=constance_config.TRUSTED_DEVICE_DURATION_HOURS),
                'is_active': True
            }
        )
        return trusted_device