from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler
import logging

logger = logging.getLogger(__name__)


def _handler_authentication_error(exc, context, response):
    """
    The function returns a message indicating that an authorization token is not provided.

    :param exc: The `exc` parameter is the exception object that was raised during the authentication
    process
    :param context: The `context` parameter is a dictionary that contains additional information about
    the error that occurred. It can include details such as the request that caused the error, the user
    who made the request, or any other relevant information
    :param response: The `response` parameter is the HTTP response object that will be returned to the
    client. It contains information such as the status code, headers, and body of the response
    :return: the string "An authorization token is not provided."
    """
    return "An authorization token is not provided.", 'authorization_token_not_provided', 400


def _handler_invalid_token_error(exc, context, response):
    """
    The function handles an invalid token error by returning a specific error message.

    :param exc: The `exc` parameter represents the exception that was raised. In this case, it would be
    an invalid token error
    :param context: The `context` parameter is a dictionary that contains additional information about
    the error that occurred. It can include details such as the request that caused the error, the user
    who made the request, or any other relevant information
    :param response: The `response` parameter is the HTTP response object that will be returned to the
    client. It contains information such as the status code, headers, and body of the response
    :return: the string "An authorization token is not valid."
    """
    return "An authorization token is not valid.", 'authorization_token_not_valid', 400


def _handler_validation_error(exc, context, response):
    """
    The function `_handler_validation_error` handles validation errors by extracting the error code and
    value, and returning a custom error message based on the code.

    :param exc: The `exc` parameter is an exception object that is raised when a validation error
    occurs. It contains information about the error, such as the field that failed validation and the
    error code
    :param context: The `context` parameter is a dictionary that contains additional information about
    the exception that occurred. It can include details such as the request, view, and args that were
    being processed when the exception occurred
    :param response: The `response` parameter is the response object that will be returned by the
    handler. It is used to modify the response if needed
    :return: a message based on the validation error code.
    """
    key = list(list(exc.__dict__.values())[0].keys())[0]
    message = ''
    try:
        code = list(list(exc.__dict__.values())[0].values())[0][0].__dict__['code']
        value = list(list(exc.__dict__.values())[0].values())[0][0]
    except:
        code = list(list(exc.__dict__.values())[0].values())[0][0][0].__dict__['code']
        value = list(list(exc.__dict__.values())[0].values())[0][0][0]
    custom_msg_code = ["required", "null", "blank"]
    if code in custom_msg_code:
        message = f"{key} field is required"
    elif code:
        message = f"{value}"
    return message, key, 400


def custom_exception_handler(exc, context):
    """
    The function `custom_exception_handler` handles custom exceptions by mapping them to specific
    handlers and returning a response with the appropriate status code and message.

    :param exc: The `exc` parameter is the exception object that was raised. It contains information
    about the exception, such as its type, message, and traceback
    :param context: The `context` parameter in the `custom_exception_handler` function is a dictionary
    that contains information about the current request and view that raised the exception. It typically
    includes the following keys:
    :return: a response object.
    """
    try:
        exception_class = exc.__class__.__name__
        handlers = {
            # 'NotAuthenticated': _handler_authentication_error,
            # 'InvalidToken': _handler_invalid_token_error,
            'ValidationError': _handler_validation_error,
            # Add more handlers as needed
        }
        res = exception_handler(exc, context)
        code = ''
        extra = None
        if exception_class in handlers:
            # calling hanlder based on the custom
            message, code, status = handlers[exception_class](exc, context, res)
        elif isinstance(exc, APIException):
            message = exc.detail
            code = exc.get_codes()
            if hasattr(exc, 'extra') and getattr(exc, 'extra') is not None:
                extra = getattr(exc, 'extra')
        else:
            # if there is no hanlder is presnet
            message = str(exc)

        if getattr(res, 'status_code', 500) == 401:
            return Response(data=message, status=401)
        rs = {
            'detail': message,
            'code': code,
            'status_code': getattr(res, 'status_code', 500)
        }
        if extra is not None:
            rs['extra'] = extra
        return Response(data=rs, status=rs.get('status_code'))
    except Exception as e:
        logger.error(str(e))
