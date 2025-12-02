from django.contrib.auth import get_user_model
from django.urls import reverse

from apps.accounts.tests.test_factory import UserFactory

UserModel = get_user_model()


class TestUserConstants:
    def init_main_constants(self):
        self.user_email = 'staff@domain.com'
        self.user_password = '_123Qwe_*'

    def init_register_user(self):
        user_staff_obj = UserFactory(email=self.user_email)
        user_staff_obj.set_password(self.user_password)
        user_staff_obj.save()
        return user_staff_obj

    def login_user(self, email, pw, client):
        """ Login the user passed and set token to client obj """
        data = {'email': email, 'password': pw}
        rs = client.post(reverse('accounts:login'), data, format='json')
        assert rs.status_code == 200
        rs_body = rs.data
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + rs_body.get('tokens').get('access'))
        return rs_body
