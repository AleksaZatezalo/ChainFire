from rest_framework import serializers
from .models import Scan, SemgrepRule, NucleiTemplate, Wordlist


class SemgrepRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = SemgrepRule
        fields = ["id", "name", "content", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class NucleiTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = NucleiTemplate
        fields = ["id", "name", "content", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class WordlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wordlist
        fields = ["id", "name", "content", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class ScanCreateSerializer(serializers.ModelSerializer):
    """Accepts only the writable fields when creating a scan."""

    class Meta:
        model = Scan
        fields = [
            "label",
            "target_url",
            "source_path",
            "scan_mode",
            "semgrep_rule",
            "nuclei_template",
            "wordlist",
            "min_severity",
        ]


class ScanDetailSerializer(serializers.ModelSerializer):
    """Full scan detail including results."""

    semgrep_rule_name = serializers.SerializerMethodField()
    nuclei_template_name = serializers.SerializerMethodField()
    wordlist_name = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "label",
            "target_url",
            "source_path",
            "scan_mode",
            "semgrep_rule",
            "semgrep_rule_name",
            "nuclei_template",
            "nuclei_template_name",
            "wordlist",
            "wordlist_name",
            "min_severity",
            "status",
            "semgrep_findings",
            "nuclei_findings",
            "nuclei_tags",
            "error_message",
            "created_at",
            "started_at",
            "completed_at",
        ]
        read_only_fields = fields

    def get_semgrep_rule_name(self, obj: Scan) -> str | None:
        return obj.semgrep_rule.name if obj.semgrep_rule else None

    def get_nuclei_template_name(self, obj: Scan) -> str | None:
        return obj.nuclei_template.name if obj.nuclei_template else None

    def get_wordlist_name(self, obj: Scan) -> str | None:
        return obj.wordlist.name if obj.wordlist else None


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views — no finding payloads."""

    semgrep_count = serializers.SerializerMethodField()
    nuclei_count = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "label",
            "target_url",
            "status",
            "semgrep_count",
            "nuclei_count",
            "created_at",
            "completed_at",
        ]

    def get_semgrep_count(self, obj: Scan) -> int:
        return len(obj.semgrep_findings)

    def get_nuclei_count(self, obj: Scan) -> int:
        return len(obj.nuclei_findings)
