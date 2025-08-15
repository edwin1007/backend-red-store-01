from django.urls import path
from . import views
from .views import LoginView
from .views import PasswordResetRequestView
from .views import PasswordResetConfirmView

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("profile/", views.get_user_profile, name="profile"),
    path("password-reset-request/", PasswordResetRequestView.as_view(),
         name="password-reset-request"),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view(),
         name="password_reset_confirm"),
]
