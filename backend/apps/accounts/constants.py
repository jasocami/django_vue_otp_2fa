from django.db import models


class OTPChoices(models.TextChoices):
    LOGIN = 'login', 'Login'
    SIGN = 'sign', 'Sign'
    APP = 'app', 'App'
