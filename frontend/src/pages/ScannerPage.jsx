import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  scansApi,
  semgrepRulesApi,
  nucleiTemplatesApi,
  wordlistsApi,
  healthApi,
} from "../api/client.js";

const SEVERITY_OPTIONS = [
  { value: "info",     label: "Info (all)" },
  { value: "warning",  label: "Warning" },
  { value: "error",    label: "Error" },
  { value: "critical", label: "Critical only" },
];

const SCAN_MODES = [
  {
    value: "semgrep_all",
    label: "Chained Scan",
    tag: "Recommended",
    tagColor: "var(--green-light)",
    description:
      "Semgrep scans the source code with its full auto-detected ruleset. " +
      "Findings are mapped to nuclei tags so only relevant DAST templates run. " +
      "Fast and targeted.",
  },
  {
    value: "custom",
    label: "Custom Rules",
    tag: null,
    description:
      "Select a specific semgrep rule and nuclei template. " +
      "Semgrep findings are mapped to nuclei tags to combine with " +
      "your chosen template.",
  },
];

const sectionHeading = {
  fontSize: 13,
  fontWeight: 600,
  marginBottom: 14,
  color: "var(--text-muted)",
  textTransform: "uppercase",
  letterSpacing: "0.5px",
};

const hint = { color: "var(--text-muted)", fontSize: 12, marginTop: 4, lineHeight: 1.5 };

function HealthBadge({ tool, available }) {
  return (
    <span
      className={`badge badge-${available ? "completed" : "failed"}`}
      style={{ marginRight: 8 }}
    >
      {tool}: {available ? "ready" : "not found"}
    </span>
  );
}

function ModeCard({ mode, selected, onSelect }) {
  return (
    <label
      onClick={onSelect}
      style={{
        display: "block",
        padding: "12px 14px",
        borderRadius: "var(--radius)",
        border: `1px solid ${selected ? "var(--green)" : "var(--border)"}`,
        background: selected ? "rgba(35,134,54,0.08)" : "transparent",
        cursor: "pointer",
        userSelect: "none",
        transition: "border-color 0.15s, background 0.15s",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
        <span
          style={{
            display: "inline-block",
            width: 14,
            height: 14,
            borderRadius: "50%",
            border: `2px solid ${selected ? "var(--green)" : "var(--border)"}`,
            background: selected ? "var(--green)" : "transparent",
            flexShrink: 0,
            marginTop: 3,
            transition: "border-color 0.15s, background 0.15s",
          }}
        />
        <div>
          <div style={{ fontWeight: 600, marginBottom: 3 }}>
            {mode.label}
            {mode.tag && (
              <span style={{ color: mode.tagColor, fontSize: 11, marginLeft: 8, fontWeight: 500 }}>
                {mode.tag}
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
            {mode.description}
          </div>
        </div>
      </div>
    </label>
  );
}

export default function ScannerPage() {
  const navigate = useNavigate();

  const [scanMode, setScanMode] = useState("semgrep_all");
  const [form, setForm] = useState({
    label:           "",
    target_url:      "",
    source_path:     "",
    semgrep_rule:    "",
    nuclei_template: "",
    wordlist:        "",
    min_severity:    "info",
  });
  const [errors, setErrors]           = useState({});
  const [submitError, setSubmitError] = useState(null);
  const [submitting, setSubmitting]   = useState(false);

  const [rules, setRules]         = useState([]);
  const [templates, setTemplates] = useState([]);
  const [wordlists, setWordlists] = useState([]);
  const [health, setHealth]       = useState(null);

  useEffect(() => {
    semgrepRulesApi.list().then((r) => setRules(r.data)).catch(() => {});
    nucleiTemplatesApi.list().then((r) => setTemplates(r.data)).catch(() => {});
    wordlistsApi.list().then((r) => setWordlists(r.data)).catch(() => {});
    healthApi.check().then((r) => setHealth(r.data)).catch(() => {});
  }, []);

  const set = (field) => (e) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const validate = () => {
    const errs = {};
    if (!form.target_url.trim()) errs.target_url = "Target URL is required.";
    if (scanMode === "custom" && form.source_path.trim() && !form.semgrep_rule) {
      errs.semgrep_rule = "Select a semgrep rule when providing a source path in custom mode.";
    }
    return errs;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setErrors({});
    setSubmitError(null);

    const payload = {
      label:        form.label.trim() || undefined,
      target_url:   form.target_url.trim(),
      source_path:  form.source_path.trim() || "",
      scan_mode:    scanMode,
      min_severity: form.min_severity,
    };

    if (form.wordlist) payload.wordlist = form.wordlist;

    // Custom rule/template only sent in custom mode
    if (scanMode === "custom") {
      if (form.semgrep_rule)    payload.semgrep_rule    = form.semgrep_rule;
      if (form.nuclei_template) payload.nuclei_template = form.nuclei_template;
    }

    try {
      setSubmitting(true);
      await scansApi.create(payload);
      navigate("/results");
    } catch (err) {
      setSubmitError(
        err?.response?.data?.target_url?.[0] ||
        err?.response?.data?.detail ||
        "Failed to start scan."
      );
    } finally {
      setSubmitting(false);
    }
  };

  const isCustom = scanMode === "custom";

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Scanner</h1>
          <p className="page-subtitle">Configure and launch a new DAST scan.</p>
        </div>
      </div>

      {health && (
        <div style={{ marginBottom: 20 }}>
          <HealthBadge tool="semgrep" available={health.semgrep?.available} />
          <HealthBadge tool="nuclei"  available={health.nuclei?.available} />
        </div>
      )}

      {submitError && <div className="alert alert-error">{submitError}</div>}

      <form onSubmit={handleSubmit}>

        {/* ── Scan mode ─────────────────────────────────────────────────── */}
        <div className="card card-body" style={{ marginBottom: 16 }}>
          <h2 style={sectionHeading}>Scan Mode</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {SCAN_MODES.map((mode) => (
              <ModeCard
                key={mode.value}
                mode={mode}
                selected={scanMode === mode.value}
                onSelect={() => setScanMode(mode.value)}
              />
            ))}
          </div>
        </div>

        {/* ── Target ────────────────────────────────────────────────────── */}
        <div className="card card-body" style={{ marginBottom: 16 }}>
          <h2 style={sectionHeading}>Target</h2>

          <div className="form-group">
            <label className="form-label">Label (optional)</label>
            <input
              className="form-control"
              type="text"
              placeholder="e.g. staging-api-scan"
              value={form.label}
              onChange={set("label")}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Target URL *</label>
            <input
              className="form-control"
              type="url"
              placeholder="http://127.0.0.1:5000"
              value={form.target_url}
              onChange={set("target_url")}
              style={errors.target_url ? { borderColor: "var(--red)" } : {}}
            />
            {errors.target_url && (
              <p style={{ color: "var(--red-light)", fontSize: 12, marginTop: 4 }}>
                {errors.target_url}
              </p>
            )}
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Wordlist</label>
            <select className="form-control" value={form.wordlist} onChange={set("wordlist")}>
              <option value="">— Target URL only —</option>
              {wordlists.map((w) => (
                <option key={w.id} value={w.id}>{w.name}</option>
              ))}
            </select>
            <p style={hint}>Paths are combined with the target URL to form the full nuclei target list.</p>
          </div>
        </div>

        {/* ── Semgrep SAST ──────────────────────────────────────────────── */}
        <div className="card card-body" style={{ marginBottom: 16 }}>
          <h2 style={sectionHeading}>Semgrep SAST (optional)</h2>

          <div className="form-group" style={{ marginBottom: isCustom ? 16 : 0 }}>
            <label className="form-label">Source Code Path</label>
            <input
              className="form-control"
              type="text"
              placeholder="/workspace/source"
              value={form.source_path}
              onChange={set("source_path")}
            />
            <p style={hint}>
              <strong>To scan a local directory:</strong> set{" "}
              <code style={{ fontFamily: "var(--font-mono)", background: "rgba(255,255,255,0.05)", padding: "1px 4px", borderRadius: 3 }}>
                SOURCE_DIR=/path/to/your/code
              </code>{" "}
              in a <code style={{ fontFamily: "var(--font-mono)", background: "rgba(255,255,255,0.05)", padding: "1px 4px", borderRadius: 3 }}>.env</code> file
              next to <code style={{ fontFamily: "var(--font-mono)", background: "rgba(255,255,255,0.05)", padding: "1px 4px", borderRadius: 3 }}>docker-compose.yml</code>,
              then restart the backend. Your directory will be mounted at{" "}
              <code style={{ fontFamily: "var(--font-mono)", background: "rgba(255,255,255,0.05)", padding: "1px 4px", borderRadius: 3 }}>/workspace/source</code>.
              {!isCustom ? " Semgrep will use its full auto-detected ruleset." : ""}
            </p>
          </div>

          {/* Custom rule selector — only visible in custom mode */}
          {isCustom && (
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Semgrep Rule</label>
              <select
                className="form-control"
                value={form.semgrep_rule}
                onChange={set("semgrep_rule")}
                style={errors.semgrep_rule ? { borderColor: "var(--red)" } : {}}
              >
                <option value="">— Select a rule —</option>
                {rules.map((r) => (
                  <option key={r.id} value={r.id}>{r.name}</option>
                ))}
              </select>
              {errors.semgrep_rule && (
                <p style={{ color: "var(--red-light)", fontSize: 12, marginTop: 4 }}>
                  {errors.semgrep_rule}
                </p>
              )}
              <p style={hint}>Findings are mapped to nuclei tags to focus the DAST phase.</p>
            </div>
          )}
        </div>

        {/* ── Nuclei DAST ───────────────────────────────────────────────── */}
        <div className="card card-body" style={{ marginBottom: 24 }}>
          <h2 style={sectionHeading}>Nuclei DAST</h2>

          {!isCustom && (
            <div className="alert alert-info" style={{ marginBottom: 14 }}>
              <strong>Chained Scan:</strong> nuclei templates are selected by mapping semgrep findings
              to vulnerability tags (e.g. <code style={{ fontFamily: "var(--font-mono)" }}>pickle.loads</code> →{" "}
              <code style={{ fontFamily: "var(--font-mono)" }}>rce,deserialization</code>).
              Only matching templates run.
            </div>
          )}

          {/* Custom template selector — only visible in custom mode */}
          {isCustom && (
            <div className="form-group">
              <label className="form-label">Nuclei Template (optional)</label>
              <select
                className="form-control"
                value={form.nuclei_template}
                onChange={set("nuclei_template")}
              >
                <option value="">— Use tags from semgrep (or scan broadly) —</option>
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
          )}

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Minimum Severity for Tag Mapping</label>
            <select
              className="form-control"
              value={form.min_severity}
              onChange={set("min_severity")}
            >
              {SEVERITY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
            <p style={hint}>
              Only semgrep findings at or above this severity influence which nuclei tags are selected.
            </p>
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={submitting}
            style={{ padding: "8px 24px" }}
          >
            {submitting ? "Starting…" : "▶ Start Scan"}
          </button>
        </div>
      </form>
    </>
  );
}
