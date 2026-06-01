from django.urls import path
from . import views

urlpatterns = [
    path("csrf/",              views.csrf_view,             name="auth-csrf"),
    path("me/",               views.me_view,               name="auth-me"),
    path("register/",         views.register_view,         name="auth-register"),
    path("login/",            views.login_view,            name="auth-login"),
    path("logout/",           views.logout_view,           name="auth-logout"),
    path("security-question/", views.security_question_view, name="auth-security-question"),
    path("reset-password/",   views.reset_password_view,  name="auth-reset-password"),
    # Admin
    path("users/",                        views.admin_users_view,       name="admin-users"),
    path("users/<int:user_id>/approve/",  views.admin_approve_view,     name="admin-approve"),
    path("users/<int:user_id>/revoke/",   views.admin_revoke_view,      name="admin-revoke"),
    path("users/<int:user_id>/",          views.admin_delete_user_view, name="admin-delete-user"),
]
