from __future__ import annotations

import shutil
from datetime import timedelta

from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from .models import NucleiTemplate, Scan, ScheduledScan, SemgrepRule, Wordlist
from .serializers import (
    NucleiTemplateSerializer,
    ScanCreateSerializer,
    ScanDetailSerializer,
    ScanListSerializer,
    ScheduledScanSerializer,
    SemgrepRuleSerializer,
    WordlistSerializer,
)
from .services.scan_runner import start_scan


class SemgrepRuleViewSet(ModelViewSet):
    queryset = SemgrepRule.objects.all()
    serializer_class = SemgrepRuleSerializer
    http_method_names = ["get", "post", "put", "delete", "head", "options"]


class NucleiTemplateViewSet(ModelViewSet):
    queryset = NucleiTemplate.objects.all()
    serializer_class = NucleiTemplateSerializer
    http_method_names = ["get", "post", "put", "delete", "head", "options"]


class WordlistViewSet(ModelViewSet):
    queryset = Wordlist.objects.all()
    serializer_class = WordlistSerializer
    http_method_names = ["get", "post", "put", "delete", "head", "options"]


class ScanViewSet(ModelViewSet):
    queryset = Scan.objects.all()
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_serializer_class(self):
        if self.action == "list":
            return ScanListSerializer
        if self.action == "create":
            return ScanCreateSerializer
        return ScanDetailSerializer

    def perform_create(self, serializer):
        scan = serializer.save()
        start_scan(str(scan.id))


class ScheduledScanViewSet(ModelViewSet):
    queryset = ScheduledScan.objects.all()
    serializer_class = ScheduledScanSerializer
    http_method_names = ["get", "post", "put", "patch", "delete", "head", "options"]

    def perform_create(self, serializer):
        interval = serializer.validated_data.get("interval", ScheduledScan.INTERVAL_24H)
        next_run = timezone.now() + timedelta(seconds=ScheduledScan.INTERVAL_SECONDS[interval])
        serializer.save(next_run=next_run)

    @action(detail=True, methods=["post"])
    def toggle(self, request, pk=None):
        sched = self.get_object()
        sched.enabled = not sched.enabled
        sched.save(update_fields=["enabled"])
        return Response(ScheduledScanSerializer(sched).data)


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """Return the availability and version of semgrep and nuclei binaries."""
    semgrep_path = shutil.which("semgrep")
    nuclei_path = shutil.which("nuclei")

    return Response(
        {
            "semgrep": {
                "available": semgrep_path is not None,
                "path": semgrep_path,
            },
            "nuclei": {
                "available": nuclei_path is not None,
                "path": nuclei_path,
            },
        }
    )
