import React, { useEffect, useRef, useState } from "react";
import { exploitsApi } from "../api/client.js";

const POLL_MS = 4000;

function SeverityBadge({ severity }) {
  const s = (severity || "info").toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

// ── Exploit panel ──────────────────────────────────────────────────────────────
function ExploitPanel({ scanId, findingIndex }) {
  const [exploit, setExploit] = useState(null);   // ExploitResult object
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [copied, setCopied]   = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const pollRef = useRef(null);

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  useEffect(() => () => stopPolling(), []);

  const pollStatus = (id) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const res = await exploitsApi.get(id);
        setExploit(res.data);
        if (res.data.status === "completed" || res.data.status === "failed") {
          stopPolling();
          setLoading(false);
        }
      } catch { /* ignore poll errors */ }
    }, POLL_MS);
  };

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    setExploit(null);
    try {
      const res = await exploitsApi.generate(scanId, findingIndex);
      setExploit(res.data);
      if (res.data.status !== "completed" && res.data.status !== "failed") {
        pollStatus(res.data.id);
      } else {
        setLoading(false);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to start exploit generation.");
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (exploit?.exploit_code) {
      navigator.clipboard.writeText(exploit.exploit_code).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  const handleDownload = () => {
    if (!exploit?.exploit_code) return;
    const blob = new Blob([exploit.exploit_code], { type: "text/x-python" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = "exploit.py";
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2000);
  };

  const isRunning = loading || exploit?.status === "pending" || exploit?.status === "running";

  return (
    <div className="exploit-panel">
      <div className="exploit-panel-header">
        <span style={{ fontWeight: 600, fontSize: 13 }}>⚡ Exploit Generation</span>
        <button
          className="btn btn-secondary btn-sm"
          onClick={handleGenerate}
          disabled={isRunning}
        >
          {isRunning
            ? <><span className="spinner" style={{ width: 11, height: 11 }} /> Generating…</>
            : exploit ? "↺ Regenerate" : "Generate Exploit"
          }
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ margin: "12px 0 0" }}>{error}</div>
      )}

      {isRunning && !exploit && (
        <div className="exploit-thinking">
          <span className="spinner" />
          <span>Claude is probing the target and crafting an exploit…</span>
        </div>
      )}

      {exploit?.status === "running" && (
        <div className="exploit-thinking">
          <span className="spinner" />
          <span>
            Agent is working
            {exploit.agent_log?.length > 0
              ? ` — ${exploit.agent_log.length} tool call${exploit.agent_log.length !== 1 ? "s" : ""} so far`
              : "…"}
          </span>
        </div>
      )}

      {exploit?.status === "failed" && (
        <div className="alert alert-error" style={{ margin: "12px 0 0" }}>
          <strong>Generation failed:</strong> {exploit.error_message}
        </div>
      )}

      {exploit?.status === "completed" && exploit.exploit_code && (
        <div className="exploit-result">
          {exploit.agent_log?.length > 0 && (
            <div className="exploit-log">
              <div className="exploit-log-title">Agent trace ({exploit.agent_log.length} tool calls)</div>
              {exploit.agent_log.map((entry, i) => (
                <div key={i} className="exploit-log-entry">
                  <span className="exploit-log-tool">{entry.tool}</span>
                  <span className="exploit-log-path">
                    {entry.tool === "http_request"
                      ? `${entry.input?.method} ${entry.input?.path}`
                      : "(script)"}
                  </span>
                </div>
              ))}
            </div>
          )}
          <div className="exploit-code-header">
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>exploit.py</span>
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn btn-secondary btn-sm" onClick={handleDownload}>
                {downloaded ? "✓ Saved" : "↓ Download"}
              </button>
              <button className="btn btn-secondary btn-sm" onClick={handleCopy}>
                {copied ? "✓ Copied" : "Copy"}
              </button>
            </div>
          </div>
          <pre className="exploit-code">{exploit.exploit_code}</pre>
        </div>
      )}
    </div>
  );
}

// ── Semgrep row ────────────────────────────────────────────────────────────────
function SemgrepRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const loc    = finding.location || {};
  const filePath = loc.file_path
    ? `${loc.file_path}${loc.line ? `:${loc.line}` : ""}`
    : "—";

  return (
    <>
      <tr onClick={() => setExpanded((v) => !v)} style={{ cursor: "pointer" }}>
        <td className="text-muted text-sm">{index + 1}</td>
        <td><SeverityBadge severity={finding.severity} /></td>
        <td className="font-mono truncate" style={{ maxWidth: 240 }}>{finding.check_id || "—"}</td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 300 }}>{filePath}</td>
        <td style={{ color: "var(--text-muted)", fontSize: 12 }}>{expanded ? "▲" : "▼"}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} style={{ padding: "0 14px 12px" }}>
            <pre className="finding-detail">{finding.message || "(no message)"}</pre>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Nuclei row ─────────────────────────────────────────────────────────────────
function NucleiRow({ finding, index, scanId }) {
  const [expanded, setExpanded]           = useState(false);
  const [showExploit, setShowExploit]     = useState(false);
  const info    = finding.info || {};
  const sev     = info.severity || "info";
  const name    = info.name || finding["template-id"] || "—";
  const matched = finding["matched-at"] || finding.host || "—";
  const param   = finding["fuzzing-parameter"] || finding.fuzzing_parameter || "";

  return (
    <>
      <tr onClick={() => setExpanded((v) => !v)} style={{ cursor: "pointer" }}>
        <td className="text-muted text-sm">{index + 1}</td>
        <td><SeverityBadge severity={sev} /></td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 200 }}>
          {finding["template-id"] || "—"}
        </td>
        <td style={{ fontWeight: 500 }}>{name}</td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 260 }}>{matched}</td>
        <td onClick={(e) => e.stopPropagation()}>
          <button
            className="btn btn-secondary btn-sm"
            style={{ whiteSpace: "nowrap" }}
            onClick={() => { setShowExploit((v) => !v); setExpanded(true); }}
          >
            ⚡ {showExploit ? "Hide" : "Exploit"}
          </button>
        </td>
        <td style={{ color: "var(--text-muted)", fontSize: 12 }}>{expanded ? "▲" : "▼"}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} style={{ padding: "0 14px 12px" }}>
            <pre className="finding-detail">
              {JSON.stringify(
                { ...finding, info: undefined, "template-id": undefined },
                null,
                2
              )}
            </pre>
            {param && (
              <p style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
                Parameter: <strong>{param}</strong>
              </p>
            )}
            {showExploit && scanId && (
              <ExploitPanel scanId={scanId} findingIndex={index} />
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ── Public component ───────────────────────────────────────────────────────────
export default function FindingsTable({ type, findings, scanId }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 32 }}>
        <span className="empty-state-icon">✅</span>
        <p className="empty-state-title">No findings</p>
        <p className="empty-state-body">
          {type === "semgrep"
            ? "Semgrep did not flag anything with the selected rule."
            : "Nuclei did not detect any vulnerabilities."}
        </p>
      </div>
    );
  }

  if (type === "semgrep") {
    return (
      <div className="table-wrapper">
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Location</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <SemgrepRow key={i} finding={f} index={i} />
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table className="table">
        <thead>
          <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Template ID</th>
            <th>Name</th>
            <th>Matched At</th>
            <th />
            <th />
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <NucleiRow key={i} finding={f} index={i} scanId={scanId} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
