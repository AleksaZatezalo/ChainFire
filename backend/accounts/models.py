from django.contrib.auth.models import User
from django.db import models

SECURITY_QUESTIONS = [
    ("pet",    "What was the name of your first pet?"),
    ("city",   "What city were you born in?"),
    ("school", "What was the name of your primary school?"),
    ("mother", "What is your mother's maiden name?"),
    ("street", "What street did you grow up on?"),
    ("car",    "What was the make of your first car?"),
]


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    is_approved = models.BooleanField(default=False)
    security_question = models.CharField(
        max_length=20, choices=SECURITY_QUESTIONS, default="pet"
    )
    # Stored as a Django password hash via make_password/check_password
    security_answer_hash = models.CharField(max_length=256)

    def __str__(self) -> str:
        return f"Profile({self.user.username})"
