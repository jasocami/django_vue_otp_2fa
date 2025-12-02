import logging

from constance import config as constance_config
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import loader

logger = logging.getLogger(__name__)


class Communication:

    def send_email(self, subject, body, from_email=None, to=None, attachments=None):
        """ Send email base """

        from_email = from_email or settings.DEFAULT_FROM_EMAIL

        try:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=body,
                from_email=from_email,
                to=to,
                attachments=attachments,
            )
            msg.attach_alternative(body, "text/html")
            msg.send()
            logger.info('email sent')
            return True
        except Exception as e:
            logger.error(str(e))
            return False

    def send_forgot_password_email(self, user, token):
        """
        Send feedback em email.
        Context needs 'user', 'frontend_url' and 'token'
        """

        subject_template_name = 'email_forgot_password_subject.txt'
        body_template_name = 'email_forgot_password_body.html'

        subject = loader.render_to_string(subject_template_name, {'user': user})
        subject = ''.join(subject.splitlines())
        context = {
            'user': user,
            'frontend_url': '{}/#/forgot-password/{}/'.format(constance_config.FRONTEND_URL, token),
            'token': token
        }
        body = loader.render_to_string(body_template_name, context)
        return self.send_email(subject, body, to=[user.email])

    def send_update_expired_password_email(self, user, token):
        """
        Send expired password url email.
        Context needs 'user', 'frontend_url' and 'token'
        """

        subject_template_name = 'email_update_expired_password_subject.txt'
        body_template_name = 'email_update_expired_password_body.html'

        subject = loader.render_to_string(subject_template_name, {'user': user})
        subject = ''.join(subject.splitlines())
        context = {
            'user': user,
            'frontend_url': '{}/#/update-expired-password/{}/'.format(constance_config.FRONTEND_URL, token),
            'token': token
        }
        body = loader.render_to_string(body_template_name, context)
        return self.send_email(subject, body, to=[user.email])

    def send_otp_email(self, user, otp_code):
        """ Send an email to create a new bucket. """

        subject_template_name = 'email_otp_subject.txt'
        body_template_name = 'email_otp_body.html'

        subject = loader.render_to_string(subject_template_name)
        subject = ''.join(subject.splitlines())
        context = {
            'user': user,
            'otp_code': otp_code,
            'expiration_minutes': constance_config.OTP_EXPIRE_MINUTES
        }
        body = loader.render_to_string(body_template_name, context)
        return self.send_email(subject, body, to=[user.email])
