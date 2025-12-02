from rest_framework import status, exceptions
from rest_framework.exceptions import APIException, NotFound


# Generic


class ExpectedParametersException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Expected to receive parameters'
    default_code = 'expected_parameters'


class UpdateListException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Error updating a list'
    default_code = 'update_list'


class SendEmailError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Error sending an email'
    default_code = 'send_email_error'


class DeleteException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Error deleting'
    default_code = 'delete_error'


class NotFoundException(NotFound):
    default_detail = 'Not found'


# User


class CreateUserException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Error creating a user'
    default_code = 'create_user'


class UpdateUserException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Error updating a user'
    default_code = 'update_user'


class CreateUserEmailException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Email exists'
    default_code = 'email_exists'


class DeleteMeUserException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Deleting your own user is not allowed'
    default_code = 'delete_my_own_user'


class OnlyAdminException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Only admin can do this action'
    default_code = 'only_admin_are_allowed'


# OTP


class OTPCodeInvalidExpiredException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'OTP code invalid or expired'
    default_code = 'otp_code_invalid_expired'


# Auth


class IncorrectTokenException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Incorrect token'
    default_code = 'incorrect_token'


class AuthenticationFailedException(exceptions.AuthenticationFailed):
    status_code = status.HTTP_400_BAD_REQUEST


class PasswordNotValidException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Password not valid'
    default_code = 'password_not_valid'


class PasswordExpiredException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Password expired'
    default_code = 'password_expired'


class NoActiveAccountException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'No active account'
    default_code = 'no_active_account'


class LogoutNotPossibleException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Logout has not been possible'
    default_code = 'no_logout'
