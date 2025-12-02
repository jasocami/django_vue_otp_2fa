from django.urls import path, include
from rest_framework import routers

from apps.accounts.views.auth_views import LogoutView, LoginView, CustomTokenRefreshView
from apps.accounts.views.otp_views import VerifyOtpAPIView, ReSendOTPAPIView
from apps.accounts.views.views import UserViewSet

app_name = "accounts"

route = routers.SimpleRouter()
route.register('', UserViewSet)

urlpatterns = [
    path('logout/', LogoutView.as_view(), name='rest_logout'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path("verify-otp/", VerifyOtpAPIView.as_view(), name="verify_otp"),
    path("resend-otp/", ReSendOTPAPIView.as_view(), name="resend_otp"),
    path('', include(route.urls)),
]
