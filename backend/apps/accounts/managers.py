from django.contrib.auth.models import BaseUserManager


class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email, and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password is not None:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """ Create a normal user """

        extra_fields.setdefault('role', None)
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """ Create a superuser user """

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, password, **extra_fields)

    def only_active(self):
        return self.get_queryset().filter(is_active=True)

    def exclude_anonymized_users(self):
        return self.get_queryset().exclude(email__icontains=self.model.ANONYMIZE_EMAIL_DOMAIN)

    def exclude_anonymized_and_staff_users(self):
        return self.get_queryset().exclude(email__icontains=self.model.ANONYMIZE_EMAIL_DOMAIN, is_staff=True)

    def only_active_and_non_anonymized_users(self):
        return self.get_queryset()\
            .filter(is_active=True)\
            .exclude(email__icontains=self.model.ANONYMIZE_EMAIL_DOMAIN)
