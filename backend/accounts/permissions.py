from rest_framework.permissions import BasePermission


class IsApprovedUser(BasePermission):
    """Allow access only to authenticated users whose account is approved.
    Admins (is_staff=True) are always considered approved.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff:
            return True
        try:
            return user.profile.is_approved
        except Exception:
            return False
