from __future__ import annotations

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.response import Response

from .models import SECURITY_QUESTIONS, ApiKey, UserProfile


# ── Helpers ───────────────────────────────────────────────────────────────────

class IsStaff(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_staff
        )


def _user_payload(user: User) -> dict:
    try:
        approved = user.is_staff or user.profile.is_approved
    except Exception:
        approved = user.is_staff
    return {
        "id": user.id,
        "username": user.username,
        "is_staff": user.is_staff,
        "is_approved": approved,
    }


# ── CSRF bootstrap ─────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([AllowAny])
def csrf_view(request):
    """Force the CSRF cookie to be set so the SPA can read it."""
    get_token(request)
    return Response({"detail": "ok"})


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    username         = request.data.get("username", "").strip()
    password         = request.data.get("password", "")
    security_question = request.data.get("security_question", "").strip()
    security_answer  = request.data.get("security_answer", "").strip().lower()

    if not all([username, password, security_question, security_answer]):
        return Response({"detail": "All fields are required."}, status=400)

    if len(password) < 6:
        return Response({"detail": "Password must be at least 6 characters."}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"detail": "Username already taken."}, status=400)

    valid_keys = {q[0] for q in SECURITY_QUESTIONS}
    if security_question not in valid_keys:
        return Response({"detail": "Invalid security question."}, status=400)

    is_first = not User.objects.exists()

    user = User.objects.create_user(username=username, password=password)
    if is_first:
        user.is_staff = True
        user.save()

    UserProfile.objects.create(
        user=user,
        is_approved=is_first,
        security_question=security_question,
        security_answer_hash=make_password(security_answer),
    )

    if is_first:
        login(request, user)
        return Response(_user_payload(user), status=201)

    return Response(
        {"detail": "Registration successful. Waiting for admin approval.", "pending": True},
        status=201,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")

    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials."}, status=401)

    if not user.is_staff:
        try:
            if not user.profile.is_approved:
                return Response(
                    {"detail": "Your account is pending admin approval."}, status=403
                )
        except UserProfile.DoesNotExist:
            return Response({"detail": "Account setup incomplete."}, status=403)

    login(request, user)
    return Response(_user_payload(user))


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    logout(request)
    return Response({"detail": "Logged out."})


@api_view(["GET"])
@permission_classes([AllowAny])
def me_view(request):
    if not request.user.is_authenticated:
        return Response({"authenticated": False})
    return Response({"authenticated": True, **_user_payload(request.user)})


# ── Password reset ─────────────────────────────────────────────────────────────

@api_view(["POST"])
@permission_classes([AllowAny])
def security_question_view(request):
    """Given a username, return their security question label."""
    username = request.data.get("username", "").strip()
    try:
        user = User.objects.get(username=username)
        profile = user.profile
        label = dict(SECURITY_QUESTIONS).get(profile.security_question, "")
        return Response({"security_question_label": label, "security_question": profile.security_question})
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        return Response({"detail": "User not found."}, status=404)


@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password_view(request):
    username        = request.data.get("username", "").strip()
    security_answer = request.data.get("security_answer", "").strip().lower()
    new_password    = request.data.get("new_password", "")

    if not all([username, security_answer, new_password]):
        return Response({"detail": "All fields are required."}, status=400)

    if len(new_password) < 6:
        return Response({"detail": "Password must be at least 6 characters."}, status=400)

    try:
        user = User.objects.get(username=username)
        profile = user.profile
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        return Response({"detail": "User not found."}, status=404)

    if not check_password(security_answer, profile.security_answer_hash):
        return Response({"detail": "Incorrect answer."}, status=400)

    user.set_password(new_password)
    user.save()
    return Response({"detail": "Password reset successfully."})


# ── Admin endpoints ────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsStaff])
def admin_users_view(request):
    users = User.objects.select_related("profile").order_by("date_joined")
    data = []
    for u in users:
        try:
            approved = u.is_staff or u.profile.is_approved
        except UserProfile.DoesNotExist:
            approved = u.is_staff
        data.append({
            "id": u.id,
            "username": u.username,
            "is_staff": u.is_staff,
            "is_approved": approved,
            "date_joined": u.date_joined,
        })
    return Response(data)


@api_view(["POST"])
@permission_classes([IsStaff])
def admin_approve_view(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    if user.is_staff:
        return Response({"detail": "Cannot modify admin accounts."}, status=400)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.is_approved = True
    profile.save(update_fields=["is_approved"])
    return Response({"detail": "User approved."})


@api_view(["POST"])
@permission_classes([IsStaff])
def admin_revoke_view(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    if user.is_staff:
        return Response({"detail": "Cannot modify admin accounts."}, status=400)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.is_approved = False
    profile.save(update_fields=["is_approved"])
    return Response({"detail": "User access revoked."})


@api_view(["DELETE"])
@permission_classes([IsStaff])
def admin_delete_user_view(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    if user.is_staff:
        return Response({"detail": "Cannot delete admin accounts."}, status=400)
    user.delete()
    return Response({"detail": "User deleted."})


# ── API Key management (admin only) ───────────────────────────────────────────

def _masked_key(key_value: str) -> str:
    if len(key_value) <= 8:
        return "****"
    return key_value[:8] + "..." + key_value[-4:]


def _api_key_payload(obj: ApiKey) -> dict:
    return {
        "id":         str(obj.id),
        "label":      obj.label,
        "provider":   obj.provider,
        "masked_key": _masked_key(obj.key_value),
        "created_at": obj.created_at,
        "updated_at": obj.updated_at,
    }


@api_view(["GET", "POST"])
@permission_classes([IsStaff])
def api_keys_view(request):
    if request.method == "GET":
        keys = ApiKey.objects.all()
        return Response([_api_key_payload(k) for k in keys])

    # POST — create
    label     = request.data.get("label", "").strip()
    provider  = request.data.get("provider", ApiKey.PROVIDER_ANTHROPIC)
    key_value = request.data.get("key_value", "").strip()

    if not label or not key_value:
        return Response({"detail": "label and key_value are required."}, status=400)

    valid_providers = {p[0] for p in ApiKey.PROVIDER_CHOICES}
    if provider not in valid_providers:
        return Response({"detail": "Invalid provider."}, status=400)

    obj = ApiKey.objects.create(label=label, provider=provider, key_value=key_value)
    return Response(_api_key_payload(obj), status=201)


@api_view(["PATCH", "DELETE"])
@permission_classes([IsStaff])
def api_key_detail_view(request, key_id):
    try:
        obj = ApiKey.objects.get(id=key_id)
    except ApiKey.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)

    if request.method == "DELETE":
        obj.delete()
        return Response({"detail": "API key deleted."})

    # PATCH — update label and/or key_value
    if "label" in request.data:
        obj.label = request.data["label"].strip() or obj.label
    if "key_value" in request.data and request.data["key_value"].strip():
        obj.key_value = request.data["key_value"].strip()
    obj.save()
    return Response(_api_key_payload(obj))
