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

from .models import ExploitResult, NucleiTemplate, Scan, ScheduledScan, SemgrepRule, Wordlist
from .serializers import (
    ExploitResultSerializer,
    NucleiTemplateSerializer,
    ScanCreateSerializer,
    ScanDetailSerializer,
    ScanListSerializer,
    ScheduledScanSerializer,
    SemgrepRuleSerializer,
    WordlistSerializer,
)
from .services.scan_runner import start_scan
from .services.exploit_runner import start_exploit_generation
from .services.report_runner import start_report_generation


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

    @action(detail=True, methods=["post"], url_path="generate-exploit")
    def generate_exploit(self, request, pk=None):
        scan = self.get_object()

        if scan.status != Scan.STATUS_COMPLETED:
            return Response(
                {"detail": "Exploit generation requires a completed scan."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        finding_index = request.data.get("finding_index")
        if finding_index is None:
            return Response(
                {"detail": "finding_index is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            finding_index = int(finding_index)
        except (TypeError, ValueError):
            return Response(
                {"detail": "finding_index must be an integer."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if finding_index < 0 or finding_index >= len(scan.nuclei_findings):
            return Response(
                {"detail": "finding_index is out of range."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get or create; reset if not currently running
        try:
            result = ExploitResult.objects.get(scan=scan, finding_index=finding_index)
            if result.status == ExploitResult.STATUS_RUNNING:
                return Response(ExploitResultSerializer(result).data)
            # Reset and re-run
            result.status        = ExploitResult.STATUS_PENDING
            result.exploit_code  = ""
            result.agent_log     = []
            result.error_message = ""
            result.completed_at  = None
            result.save()
        except ExploitResult.DoesNotExist:
            result = ExploitResult.objects.create(
                scan=scan,
                finding_index=finding_index,
                status=ExploitResult.STATUS_PENDING,
            )

        start_exploit_generation(str(result.id))
        return Response(ExploitResultSerializer(result).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="generate-report")
    def generate_report(self, request, pk=None):
        from accounts.models import ApiKey

        scan = self.get_object()

        if scan.status != Scan.STATUS_COMPLETED:
            return Response(
                {"detail": "Report generation requires a completed scan."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if scan.report_status == Scan.REPORT_STATUS_RUNNING:
            return Response(ScanDetailSerializer(scan).data)

        if not ApiKey.objects.filter(provider=ApiKey.PROVIDER_ANTHROPIC).exists():
            return Response(
                {"detail": "No Anthropic API key configured. An admin must add one in Admin → API Keys."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan.report_status = Scan.REPORT_STATUS_PENDING
        scan.ai_report     = ""
        scan.save(update_fields=["report_status", "ai_report"])

        start_report_generation(str(scan.id))
        return Response(ScanDetailSerializer(scan).data)


class ExploitResultViewSet(ModelViewSet):
    queryset = ExploitResult.objects.all()
    serializer_class = ExploitResultSerializer
    http_method_names = ["get", "delete", "head", "options"]


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
    nuclei_path  = shutil.which("nuclei")
    return Response(
        {
            "semgrep": {"available": semgrep_path is not None, "path": semgrep_path},
            "nuclei":  {"available": nuclei_path  is not None, "path": nuclei_path},
        }
    )
