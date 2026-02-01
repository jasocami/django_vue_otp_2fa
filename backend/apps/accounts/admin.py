from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, OTP, TrustedDevice


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('last_login', 'is_active', 'is_staff', 'is_superuser', 'date_joined')

    fieldsets = (
        (None, {
            'fields': ('password',)
            }),
        ('Personal info', {
            'fields': ('email', 'first_name', 'last_name')
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
    list_display = ['user', 'otp_code', 'otp_type', 'is_verified', 'is_active', 'created_at', 'expires_at', 'regenerated_at']
    list_filter = ['created_at', 'expires_at', 'regenerated_at', 'otp_type', 'is_verified', 'is_active']
    raw_id_fields = ['user']


@admin.register(TrustedDevice)
class TruestedDevice(admin.ModelAdmin):
    list_display = ['user', 'created_at', 'expires_at', 'is_active']
    list_filter = ['created_at', 'expires_at', 'is_active']