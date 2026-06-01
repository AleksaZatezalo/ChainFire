from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SemgrepRuleViewSet,
    NucleiTemplateViewSet,
    WordlistViewSet,
    ScanViewSet,
    health_check,
)

router = DefaultRouter()
router.register("semgrep-rules", SemgrepRuleViewSet, basename="semgrep-rules")
router.register("nuclei-templates", NucleiTemplateViewSet, basename="nuclei-templates")
router.register("wordlists", WordlistViewSet, basename="wordlists")
router.register("scans", ScanViewSet, basename="scans")

urlpatterns = [
    path("", include(router.urls)),
    path("health/", health_check, name="health"),
]
