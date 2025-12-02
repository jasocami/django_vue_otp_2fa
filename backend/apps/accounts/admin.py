from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, OTP


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('last_login', 'is_active', 'is_staff', 'is_superuser', 'date_joined')

    fieldsets = (
        (None, {
            'fields': ('password',)
            }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email')
            }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser'),
        }),
        ('Django permissions', {
            'classes': ['collapse in'],
            'fields': ('groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ['wide'],
            'fields': ('email',  'password1', 'password2',),
        }),
    )

    search_fields = ['email']
    ordering = ['email']
    filter_horizontal = ('groups', 'user_permissions')
    readonly_fields = ['date_joined']


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['user', 'otp_code', 'otp_type', 'is_verified', 'creation_timestamp', 'expiration_timestamp']
    list_filter = ['creation_timestamp', 'expiration_timestamp', 'otp_type', 'is_verified']
    raw_id_fields = ['user']
