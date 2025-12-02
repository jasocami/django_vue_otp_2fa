from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend, ModelBackend

UserModel = get_user_model()


class EmailAuthenticate(BaseBackend):
    """
    Email Authentication Backend

    Allows a user to sign in using an email/password pair rather than
    a username/password pair.
    """

    def authenticate(self, request=None, email=None, password=None):
        """ Authenticate a user based on email address as the user name. """
        try:
            user = UserModel.objects.get(email=email)
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            return None

    def get_user(self, user_id):
        """ Get a User object from the user_id. """
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None


class CustomModelBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None):
        return super().authenticate(request, username, password)
