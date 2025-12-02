import factory
from django.contrib.auth import get_user_model

UserModel = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):

    first_name = factory.Sequence(lambda n: 'First %s' % n)
    last_name = factory.Sequence(lambda n: 'Last %s' % n)
    is_active = True
    is_staff = False
    is_superuser = False

    class Meta:
        model = UserModel
        django_get_or_create = ('email',)
