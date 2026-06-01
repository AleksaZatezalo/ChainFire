import React, { useState, useEffect, useCallback } from "react";
import {
  scheduledScansApi,
  semgrepRulesApi,
  nucleiTemplatesApi,
  wordlistsApi,
} from "../api/client.js";

const INTERVAL_OPTIONS = [
  { value: "15m", label: "Every 15 minutes" },
  { value: "1h",  label: "Every hour" },
  { value: "6h",  label: "Every 6 hours" },
  { value: "24h", label: "Every 24 hours" },
  { value: "7d",  label: "Every 7 days" },
];

const SEVERITY_OPTIONS = [
  { value: "info",     label: "Info (all)" },
  { value: "warning",  label: "Warning" },
  { value: "error",    label: "Error" },
  { value: "critical", label: "Critical only" },
];

const SCAN_MODES = [
  { value: "semgrep_all", label: "Chained Scan" },
  { value: "custom",      label: "Custom Rules" },
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

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const EMPTY_FORM = {
  label: "",
  target_url: "",
  source_path: "",
  scan_mode: "semgrep_all",
  semgrep_rule: "",
  nuclei_template: "",
  wordlist: "",
  min_severity: "info",
  interval: "24h",
};

export default function ScheduledScansPage() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [showForm, setShowForm]   = useState(false);
  const [form, setForm]           = useState(EMPTY_FORM);
  const [submitError, setSubmitError] = useState(null);
  const [submitting, setSubmitting]   = useState(false);
  const [formErrors, setFormErrors]   = useState({});

  const [rules, setRules]         = useState([]);
  const [templates, setTemplates] = useState([]);
  const [wordlists, setWordlists] = useState([]);

  const loadSchedules = useCallback(async () => {
    try {
      const res = await scheduledScansApi.list();
      setSchedules(res.data);
      setError(null);
    } catch {
      setError("Failed to load scheduled scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSchedules();
    semgrepRulesApi.list().then((r) => setRules(r.data)).catch(() => {});
    nucleiTemplatesApi.list().then((r) => setTemplates(r.data)).catch(() => {});
    wordlistsApi.list().then((r) => setWordlists(r.data)).catch(() => {});
  }, [loadSchedules]);

  const set = (field) => (e) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const validate = () => {
    const errs = {};
    if (!form.target_url.trim()) errs.target_url = "Target URL is required.";
    return errs;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setFormErrors(errs); return; }
    setFormErrors({});
    setSubmitError(null);

    const payload = {
      label:        form.label.trim() || undefined,
      target_url:   form.target_url.trim(),
      source_path:  form.source_path.trim() || "",
      scan_mode:    form.scan_mode,
      min_severity: form.min_severity,
      interval:     form.interval,
    };

    if (form.wordlist) payload.wordlist = form.wordlist;
    if (form.scan_mode === "custom") {
      if (form.semgrep_rule)    payload.semgrep_rule    = form.semgrep_rule;
      if (form.nuclei_template) payload.nuclei_template = form.nuclei_template;
    }

    try {
      setSubmitting(true);
      await scheduledScansApi.create(payload);
      setForm(EMPTY_FORM);
      setShowForm(false);
      loadSchedules();
    } catch (err) {
      setSubmitError(
        err?.response?.data?.target_url?.[0] ||
        err?.response?.data?.detail ||
        "Failed to create schedule."
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggle = async (id) => {
    try {
      const res = await scheduledScansApi.toggle(id);
      setSchedules((prev) => prev.map((s) => (s.id === id ? res.data : s)));
    } catch {
      alert("Failed to toggle schedule.");
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this scheduled scan?")) return;
    try {
      await scheduledScansApi.delete(id);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
    } catch {
      alert("Delete failed.");
    }
  };

  const isCustom = form.scan_mode === "custom";

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Scheduled Scans</h1>
          <p className="page-subtitle">
            {schedules.length} schedule{schedules.length !== 1 ? "s" : ""} configured
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm((v) => !v)}>
          {showForm ? "✕ Cancel" : "+ New Schedule"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {/* ── Create form ─────────────────────────────────────────────────── */}
      {showForm && (
        <div className="card card-body" style={{ marginBottom: 20 }}>
          <h2 style={sectionHeading}>New Scheduled Scan</h2>

          {submitError && <div className="alert alert-error">{submitError}</div>}

          <form onSubmit={handleSubmit}>
            {/* Target */}
            <div className="form-group">
              <label className="form-label">Label (optional)</label>
              <input
                className="form-control"
                type="text"
                placeholder="e.g. nightly-api-scan"
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
                style={formErrors.target_url ? { borderColor: "var(--red)" } : {}}
              />
              {formErrors.target_url && (
                <p style={{ color: "var(--red-light)", fontSize: 12, marginTop: 4 }}>
                  {formErrors.target_url}
                </p>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">Source Code Path (optional)</label>
              <input
                className="form-control"
                type="text"
                placeholder="/workspace/source"
                value={form.source_path}
                onChange={set("source_path")}
              />
              <p style={hint}>Path inside the container to scan with semgrep.</p>
            </div>

            {/* Interval */}
            <div className="form-group">
              <label className="form-label">Interval</label>
              <select className="form-control" value={form.interval} onChange={set("interval")}>
                {INTERVAL_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>

            {/* Scan mode */}
            <div className="form-group">
              <label className="form-label">Scan Mode</label>
              <select className="form-control" value={form.scan_mode} onChange={set("scan_mode")}>
                {SCAN_MODES.map((m) => (
                  <option key={m.value} value={m.value}>{m.label}</option>
                ))}
              </select>
            </div>

            {/* Custom selectors */}
            {isCustom && (
              <>
                <div className="form-group">
                  <label className="form-label">Semgrep Rule</label>
                  <select className="form-control" value={form.semgrep_rule} onChange={set("semgrep_rule")}>
                    <option value="">— None —</option>
                    {rules.map((r) => (
                      <option key={r.id} value={r.id}>{r.name}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Nuclei Template (optional)</label>
                  <select className="form-control" value={form.nuclei_template} onChange={set("nuclei_template")}>
                    <option value="">— Use tags from semgrep —</option>
                    {templates.map((t) => (
                      <option key={t.id} value={t.id}>{t.name}</option>
                    ))}
                  </select>
                </div>
              </>
            )}

            <div className="form-group">
              <label className="form-label">Wordlist</label>
              <select className="form-control" value={form.wordlist} onChange={set("wordlist")}>
                <option value="">— Target URL only —</option>
                {wordlists.map((w) => (
                  <option key={w.id} value={w.id}>{w.name}</option>
                ))}
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Minimum Severity</label>
              <select className="form-control" value={form.min_severity} onChange={set("min_severity")}>
                {SEVERITY_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20, gap: 10 }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => { setShowForm(false); setForm(EMPTY_FORM); setSubmitError(null); }}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? "Saving…" : "Save Schedule"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Schedule list ───────────────────────────────────────────────── */}
      {loading ? (
        <div className="loading-state"><div className="spinner" /> Loading…</div>
      ) : schedules.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <span className="empty-state-icon">🕐</span>
            <p className="empty-state-title">No scheduled scans</p>
            <p className="empty-state-body">Click "+ New Schedule" to create one.</p>
          </div>
        </div>
      ) : (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Label / Target</th>
                  <th>Interval</th>
                  <th>Mode</th>
                  <th>Last Run</th>
                  <th>Next Run</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {schedules.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{s.label || "—"}</div>
                      <div className="text-muted font-mono text-sm truncate" style={{ maxWidth: 240 }}>
                        {s.target_url}
                      </div>
                    </td>
                    <td className="text-sm">{s.interval_display}</td>
                    <td className="text-sm text-muted">
                      {s.scan_mode === "semgrep_all" ? "Chained" : "Custom"}
                    </td>
                    <td className="text-muted text-sm">{formatDate(s.last_run)}</td>
                    <td className="text-muted text-sm">{formatDate(s.next_run)}</td>
                    <td>
                      <span className={`badge badge-${s.enabled ? "completed" : "failed"}`}>
                        {s.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleToggle(s.id)}
                        >
                          {s.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => handleDelete(s.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
