from rest_framework import serializers


def custom_datetime_field(**kwargs):
    return serializers.DateTimeField(format='%Y/%m/%dT%H:%M:%S', **kwargs)


def custom_date_field(**kwargs):
    return serializers.DateField(format='%Y/%m/%d', **kwargs)
