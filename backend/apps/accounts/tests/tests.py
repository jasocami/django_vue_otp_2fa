import re

from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts.tests.test_constants import TestUserConstants
from apps.generic.tests import BaseTestCase

UserModel = get_user_model()


class UserBasicTests(BaseTestCase, TestUserConstants):

    def setUp(self):
        self.init_main_constants()
        self.init_register_user()
        self.client = APIClient()

    def test_login_refresh_me_logout(self):
        data = {'email': self.user_email, 'password': self.user_password}
        rs = self.client.post(reverse('accounts:login'), data, format='json')
        self.assertEqual(rs.status_code, 200)
        self.assertIn('tokens', rs.data)
        self.assertIn('access', rs.data.get('tokens'))
        access = rs.data.get('tokens').get('access')
        self.assertIn('refresh', rs.data.get('tokens'))
        self.assertIn('user', rs.data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')

        rs = self.client.get(reverse('accounts:user-blocked'), format='json')
        self.assertEqual(rs.status_code, 403)

    def test_otp_process_ok(self):
        self.login_user(self.user_email, self.user_password, self.client)

        self.assertEqual(len(mail.outbox), 1)
        results = re.findall(r'(?:otp_code: )([0-9]{,6})', mail.outbox[0].body)
        assert len(results) == 1

        data = {'otp_code': results[0]}
        rs = self.client.post(reverse('accounts:verify_otp'), data, format='json')
        self.assertEqual(rs.status_code, 204)

        rs = self.client.get(reverse('accounts:user-blocked'), format='json')
        self.assertEqual(rs.status_code, 200)
        self.assertTrue(rs.data.get('success'))

    def test_otp_process_ko(self):
        self.login_user(self.user_email, self.user_password, self.client)

        self.assertEqual(len(mail.outbox), 1)
        results = re.findall(r'(?:otp_code: )([0-9]{,6})', mail.outbox[0].body)
        assert len(results) == 1

        data = {'otp_code': 1234}
        rs = self.client.post(reverse('accounts:verify_otp'), data, format='json')
        self.assertEqual(rs.status_code, 400)
        self.assertEqual(rs.data.get('code'), 'otp_code_invalid_expired')

        rs = self.client.get(reverse('accounts:user-blocked'), format='json')
        self.assertEqual(rs.status_code, 403)
