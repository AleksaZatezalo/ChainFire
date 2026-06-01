import React, { useState } from "react";

function SeverityBadge({ severity }) {
  const s = (severity || "info").toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

// ── Semgrep findings table ─────────────────────────────────────────────────────
function SemgrepRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const loc = finding.location || {};
  const filePath = loc.file_path
    ? `${loc.file_path}${loc.line ? `:${loc.line}` : ""}`
    : "—";

  return (
    <>
      <tr
        onClick={() => setExpanded((v) => !v)}
        style={{ cursor: "pointer" }}
      >
        <td className="text-muted text-sm">{index + 1}</td>
        <td>
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="font-mono truncate" style={{ maxWidth: 240 }}>
          {finding.check_id || "—"}
        </td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 300 }}>
          {filePath}
        </td>
        <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
          {expanded ? "▲" : "▼"}
        </td>
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

// ── Nuclei findings table ──────────────────────────────────────────────────────
function NucleiRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const info = finding.info || {};
  const sev = info.severity || "info";
  const name = info.name || finding["template-id"] || "—";
  const matched = finding["matched-at"] || finding.host || "—";
  const param = finding["fuzzing-parameter"] || finding.fuzzing_parameter || "";

  return (
    <>
      <tr
        onClick={() => setExpanded((v) => !v)}
        style={{ cursor: "pointer" }}
      >
        <td className="text-muted text-sm">{index + 1}</td>
        <td>
          <SeverityBadge severity={sev} />
        </td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 200 }}>
          {finding["template-id"] || "—"}
        </td>
        <td style={{ fontWeight: 500 }}>{name}</td>
        <td className="font-mono text-sm truncate" style={{ maxWidth: 300 }}>
          {matched}
        </td>
        <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
          {expanded ? "▲" : "▼"}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} style={{ padding: "0 14px 12px" }}>
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
          </td>
        </tr>
      )}
    </>
  );
}

// ── Public component ───────────────────────────────────────────────────────────
export default function FindingsTable({ type, findings }) {
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
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <NucleiRow key={i} finding={f} index={i} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
