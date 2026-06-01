import React, { useState, useEffect, useCallback, useRef } from "react";
import { scansApi } from "../api/client.js";
import FindingsTable from "../components/FindingsTable.jsx";
import { exportScanPdf } from "../utils/exportPdf.js";

const POLL_MS = 3000;

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function duration(start, end) {
  if (!start || !end) return "—";
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

function StatusBadge({ status }) {
  return (
    <span className={`badge badge-${status}`}>
      {status === "running" && <span className="spinner" style={{ marginRight: 4 }} />}
      {status}
    </span>
  );
}

export default function ResultsPage() {
  const [scans, setScans]           = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail]         = useState(null);
  const [detailTab, setDetailTab]   = useState("semgrep");
  const pollRef = useRef(null);

  const loadList = useCallback(async () => {
    try {
      const res = await scansApi.list();
      setScans(res.data);
      setError(null);
    } catch {
      setError("Failed to load scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (id) => {
    try {
      const res = await scansApi.get(id);
      setDetail(res.data);
    } catch {
      setDetail(null);
    }
  }, []);

  // Initial load
  useEffect(() => { loadList(); }, [loadList]);

  // Poll list while any scan is running
  useEffect(() => {
    const hasRunning = scans.some((s) => s.status === "running" || s.status === "pending");
    if (hasRunning) {
      pollRef.current = setInterval(loadList, POLL_MS);
    }
    return () => clearInterval(pollRef.current);
  }, [scans, loadList]);

  // Load detail when selection changes; poll detail if running
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    loadDetail(selectedId);

    const scan = scans.find((s) => s.id === selectedId);
    if (scan?.status === "running" || scan?.status === "pending") {
      const t = setInterval(() => loadDetail(selectedId), POLL_MS);
      return () => clearInterval(t);
    }
  }, [selectedId, scans, loadDetail]);

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("Delete this scan and its results?")) return;
    try {
      await scansApi.delete(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      if (selectedId === id) setSelectedId(null);
    } catch {
      alert("Delete failed.");
    }
  };

  const selectScan = (id) => {
    setSelectedId((prev) => (prev === id ? null : id));
    setDetailTab("semgrep");
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Results</h1>
          <p className="page-subtitle">
            {scans.length} scan{scans.length !== 1 ? "s" : ""} total
          </p>
        </div>
        <button className="btn btn-secondary" onClick={loadList}>↺ Refresh</button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <div className="loading-state"><div className="spinner" /> Loading…</div>
      ) : scans.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <span className="empty-state-icon">📋</span>
            <p className="empty-state-title">No scans yet</p>
            <p className="empty-state-body">Go to the Scanner page to start your first scan.</p>
          </div>
        </div>
      ) : (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Label / Target</th>
                  <th>Status</th>
                  <th>Semgrep</th>
                  <th>Nuclei</th>
                  <th>Started</th>
                  <th>Duration</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => selectScan(scan.id)}
                    style={{ cursor: "pointer" }}
                    className={scan.status === "running" ? "scan-row-running" : ""}
                  >
                    <td>
                      <div style={{ fontWeight: selectedId === scan.id ? 600 : 400 }}>
                        {scan.label || "—"}
                      </div>
                      <div className="text-muted font-mono text-sm truncate" style={{ maxWidth: 240 }}>
                        {scan.target_url}
                      </div>
                    </td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>{scan.semgrep_count ?? "—"}</td>
                    <td>{scan.nuclei_count ?? "—"}</td>
                    <td className="text-muted text-sm">{formatDate(scan.created_at)}</td>
                    <td className="text-muted text-sm">{duration(scan.created_at, scan.completed_at)}</td>
                    <td>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={(e) => handleDelete(e, scan.id)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedId && detail && (
        <div className="card">
          <div className="card-body" style={{ paddingBottom: 0 }}>
            <div className="flex items-center justify-between" style={{ marginBottom: 16 }}>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 600 }}>
                  {detail.label || detail.target_url}
                </h2>
                <span className="text-muted text-sm">
                  {detail.target_url}
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <StatusBadge status={detail.status} />
                {detail.status === "completed" && (
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => exportScanPdf(detail)}
                  >
                    ↓ Export PDF
                  </button>
                )}
              </div>
            </div>

            {detail.status === "failed" && detail.error_message && (
              <div className="alert alert-error" style={{ marginBottom: 16 }}>
                <strong>Error:</strong> {detail.error_message}
              </div>
            )}

            <div className="flex gap-2" style={{ marginBottom: 16, flexWrap: "wrap", fontSize: 12, color: "var(--text-muted)" }}>
              {detail.semgrep_rule_name && (
                <span>Semgrep rule: <strong>{detail.semgrep_rule_name}</strong></span>
              )}
              {detail.nuclei_template_name && (
                <span>· Nuclei template: <strong>{detail.nuclei_template_name}</strong></span>
              )}
              {detail.wordlist_name && (
                <span>· Wordlist: <strong>{detail.wordlist_name}</strong></span>
              )}
              {detail.nuclei_tags?.length > 0 && (
                <span>· Tags: <strong>{detail.nuclei_tags.join(", ")}</strong></span>
              )}
            </div>

            <div className="tab-bar">
              <button
                className={`tab-btn${detailTab === "semgrep" ? " active" : ""}`}
                onClick={() => setDetailTab("semgrep")}
              >
                Semgrep ({detail.semgrep_findings?.length ?? 0})
              </button>
              <button
                className={`tab-btn${detailTab === "nuclei" ? " active" : ""}`}
                onClick={() => setDetailTab("nuclei")}
              >
                Nuclei ({detail.nuclei_findings?.length ?? 0})
              </button>
            </div>
          </div>

          <FindingsTable
            type={detailTab}
            findings={detailTab === "semgrep" ? detail.semgrep_findings : detail.nuclei_findings}
          />
        </div>
      )}
    </>
  );
}
