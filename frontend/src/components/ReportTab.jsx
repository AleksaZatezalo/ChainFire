import React, { useEffect, useRef, useState } from "react";
import { scansApi } from "../api/client.js";

const POLL_MS = 3000;

/**
 * Minimal markdown → HTML renderer (headings, bold, code blocks, lists).
 * Keeps jsPDF dependency-free on the render side.
 */
function renderMarkdown(md) {
  if (!md) return "";
  // Escape HTML
  const escape = (s) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const lines = md.split("\n");
  const out = [];
  let inCode = false;
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      if (!inCode) {
        if (inList) { out.push("</ul>"); inList = false; }
        out.push('<pre class="report-code-block"><code>');
        inCode = true;
      } else {
        out.push("</code></pre>");
        inCode = false;
      }
      continue;
    }
    if (inCode) { out.push(escape(line)); continue; }

    // Close list if line is not a list item
    if (inList && !line.startsWith("- ") && !line.startsWith("* ")) {
      out.push("</ul>");
      inList = false;
    }

    // Headings
    if (line.startsWith("#### ")) {
      out.push(`<h4 class="report-h4">${escape(line.slice(5))}</h4>`);
    } else if (line.startsWith("### ")) {
      out.push(`<h3 class="report-h3">${escape(line.slice(4))}</h3>`);
    } else if (line.startsWith("## ")) {
      out.push(`<h2 class="report-h2">${escape(line.slice(3))}</h2>`);
    } else if (line.startsWith("# ")) {
      out.push(`<h1 class="report-h1">${escape(line.slice(2))}</h1>`);
    } else if (line.startsWith("- ") || line.startsWith("* ")) {
      if (!inList) { out.push("<ul class='report-list'>"); inList = true; }
      // inline bold/code inside list items
      out.push(`<li>${inlineFormat(escape(line.slice(2)))}</li>`);
    } else if (line.trim() === "") {
      out.push("<br/>");
    } else {
      out.push(`<p class="report-p">${inlineFormat(escape(line))}</p>`);
    }
  }
  if (inList) out.push("</ul>");
  if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

function inlineFormat(s) {
  // **bold**
  s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // `code`
  s = s.replace(/`([^`]+)`/g, '<code class="report-inline-code">$1</code>');
  return s;
}

export default function ReportTab({ scan, onReportUpdate }) {
  const [generating, setGenerating] = useState(false);
  const [error, setError]           = useState(null);
  const pollRef                     = useRef(null);

  const isActive =
    scan.report_status === "pending" || scan.report_status === "running";

  // Poll while generating
  useEffect(() => {
    if (isActive && !pollRef.current) {
      pollRef.current = setInterval(async () => {
        try {
          const res = await scansApi.get(scan.id);
          onReportUpdate(res.data);
          const s = res.data.report_status;
          if (s === "completed" || s === "failed" || !s) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setGenerating(false);
          }
        } catch { /* ignore */ }
      }, POLL_MS);
    }
    return () => {
      if (pollRef.current && !isActive) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [isActive, scan.id, onReportUpdate]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const res = await scansApi.generateReport(scan.id);
      onReportUpdate(res.data);
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        "Failed to start report generation.";
      setError(msg);
      setGenerating(false);
    }
  };

  // Scan not completed
  if (scan.status !== "completed") {
    return (
      <div className="report-tab-body">
        <div className="empty-state" style={{ padding: 40 }}>
          <span className="empty-state-icon">📄</span>
          <p className="empty-state-title">Scan not yet complete</p>
          <p className="empty-state-body">
            The AI report is available once the scan finishes.
          </p>
        </div>
      </div>
    );
  }

  // No findings at all — still allow generation, but note it
  const noFindings =
    !scan.semgrep_findings?.length && !scan.nuclei_findings?.length;

  // Active (pending / running)
  if (isActive || generating) {
    return (
      <div className="report-tab-body">
        <div className="exploit-thinking" style={{ padding: 40 }}>
          <span className="spinner" />
          <span>Claude is analysing findings and writing the report…</span>
        </div>
      </div>
    );
  }

  // Failed
  if (scan.report_status === "failed") {
    return (
      <div className="report-tab-body" style={{ padding: 20 }}>
        <div className="alert alert-error">
          <strong>Report generation failed:</strong> {scan.ai_report || "Unknown error."}
        </div>
        <button className="btn btn-primary" style={{ marginTop: 12 }} onClick={handleGenerate}>
          ↺ Retry
        </button>
      </div>
    );
  }

  // Completed — show report
  if (scan.report_status === "completed" && scan.ai_report) {
    return (
      <div className="report-tab-body">
        <div
          className="report-content"
          dangerouslySetInnerHTML={{ __html: renderMarkdown(scan.ai_report) }}
        />
      </div>
    );
  }

  // Not yet generated — show generate button (or placeholder if no API key)
  return (
    <div className="report-tab-body">
      {error && (
        <div className="alert alert-error" style={{ marginBottom: 16 }}>
          {error.includes("No Anthropic API key") ? (
            <>
              <strong>No API key configured.</strong> An admin must add an Anthropic API key
              under <strong>Admin → API Keys</strong> before report generation is available.
            </>
          ) : error}
        </div>
      )}

      <div className="empty-state" style={{ padding: 40 }}>
        <span className="empty-state-icon">📄</span>
        <p className="empty-state-title">No report yet</p>
        <p className="empty-state-body">
          {noFindings
            ? "No findings to report on — the scan came back clean."
            : "Generate an AI-powered remediation report explaining each finding and how to fix it."}
        </p>
        {!noFindings && (
          <button
            className="btn btn-primary"
            style={{ marginTop: 16 }}
            onClick={handleGenerate}
            disabled={generating}
          >
            Generate Report
          </button>
        )}
      </div>
    </div>
  );
}
