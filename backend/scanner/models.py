import uuid
from django.db import models


class SemgrepRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    content = models.TextField(help_text="YAML semgrep rule definition.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        return self.name


class NucleiTemplate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    content = models.TextField(help_text="YAML nuclei template definition.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        return self.name


class Wordlist(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    content = models.TextField(
        help_text="One API path per line, e.g. /api/v1/users. Lines starting with # are ignored."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        return self.name


class Scan(models.Model):
    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    label = models.CharField(max_length=255, blank=True)
    target_url = models.URLField(help_text="Base URL of the application under test.")
    source_path = models.CharField(
        max_length=512,
        blank=True,
        help_text="Container path to source code for semgrep SAST (e.g. /workspace/myapp).",
    )
    semgrep_rule = models.ForeignKey(
        SemgrepRule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    nuclei_template = models.ForeignKey(
        NucleiTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    wordlist = models.ForeignKey(
        Wordlist,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    SCAN_MODE_SEMGREP_ALL = "semgrep_all"
    SCAN_MODE_CUSTOM      = "custom"

    SCAN_MODE_CHOICES = [
        (SCAN_MODE_SEMGREP_ALL, "Chained Scan"),
        (SCAN_MODE_CUSTOM,      "Custom Rules"),
    ]

    scan_mode = models.CharField(
        max_length=20,
        default=SCAN_MODE_SEMGREP_ALL,
        choices=SCAN_MODE_CHOICES,
        help_text=(
            "semgrep_all: semgrep auto, nuclei tag-mapped from findings. "
            "custom: selected rule + selected template."
        ),
    )
    min_severity = models.CharField(
        max_length=20,
        default="info",
        choices=[
            ("info", "Info"),
            ("warning", "Warning"),
            ("error", "Error"),
            ("critical", "Critical"),
        ],
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )
    semgrep_findings = models.JSONField(default=list)
    nuclei_findings = models.JSONField(default=list)
    nuclei_tags = models.JSONField(
        default=list, help_text="Nuclei tags derived from semgrep findings."
    )
    error_message = models.TextField(blank=True)

    REPORT_STATUS_NONE      = ""
    REPORT_STATUS_PENDING   = "pending"
    REPORT_STATUS_RUNNING   = "running"
    REPORT_STATUS_COMPLETED = "completed"
    REPORT_STATUS_FAILED    = "failed"

    report_status = models.CharField(max_length=20, blank=True, default="")
    ai_report     = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.label or f"Scan {self.id}"


class ScheduledScan(models.Model):
    INTERVAL_15M  = "15m"
    INTERVAL_1H   = "1h"
    INTERVAL_6H   = "6h"
    INTERVAL_24H  = "24h"
    INTERVAL_7D   = "7d"

    INTERVAL_CHOICES = [
        (INTERVAL_15M, "Every 15 minutes"),
        (INTERVAL_1H,  "Every hour"),
        (INTERVAL_6H,  "Every 6 hours"),
        (INTERVAL_24H, "Every 24 hours"),
        (INTERVAL_7D,  "Every 7 days"),
    ]

    INTERVAL_SECONDS = {
        INTERVAL_15M: 15 * 60,
        INTERVAL_1H:  60 * 60,
        INTERVAL_6H:  6 * 60 * 60,
        INTERVAL_24H: 24 * 60 * 60,
        INTERVAL_7D:  7 * 24 * 60 * 60,
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    label = models.CharField(max_length=255, blank=True)
    target_url = models.URLField()
    source_path = models.CharField(max_length=512, blank=True)
    scan_mode = models.CharField(
        max_length=20, default=Scan.SCAN_MODE_SEMGREP_ALL, choices=Scan.SCAN_MODE_CHOICES
    )
    semgrep_rule = models.ForeignKey(
        SemgrepRule, on_delete=models.SET_NULL, null=True, blank=True
    )
    nuclei_template = models.ForeignKey(
        NucleiTemplate, on_delete=models.SET_NULL, null=True, blank=True
    )
    wordlist = models.ForeignKey(
        Wordlist, on_delete=models.SET_NULL, null=True, blank=True
    )
    min_severity = models.CharField(max_length=20, default="info")
    interval = models.CharField(
        max_length=10, choices=INTERVAL_CHOICES, default=INTERVAL_24H
    )
    enabled = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.label or f"Schedule {self.id}"


class ExploitResult(models.Model):
    STATUS_PENDING   = "pending"
    STATUS_RUNNING   = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED    = "failed"

    STATUS_CHOICES = [
        (STATUS_PENDING,   "Pending"),
        (STATUS_RUNNING,   "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED,    "Failed"),
    ]

    id            = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan          = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="exploits")
    finding_index = models.IntegerField(help_text="Index into scan.nuclei_findings")
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    exploit_code  = models.TextField(blank=True)
    agent_log     = models.JSONField(default=list, help_text="Tool calls made during generation")
    error_message = models.TextField(blank=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    completed_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        unique_together = [("scan", "finding_index")]

    def __str__(self) -> str:
        return f"Exploit for scan {self.scan_id} finding #{self.finding_index}"
