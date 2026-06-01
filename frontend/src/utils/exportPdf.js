import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

function fmt(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function duration(start, end) {
  if (!start || !end) return "—";
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

const SEVERITY_COLORS = {
  critical: [220, 38,  38],
  error:    [234, 88,  12],
  warning:  [202, 138, 4],
  info:     [59,  130, 246],
  low:      [100, 116, 139],
};

function sevColor(sev) {
  return SEVERITY_COLORS[(sev || "info").toLowerCase()] || [100, 116, 139];
}

function addReportSection(doc, report, margin, y, pageW) {
  const usableW = pageW - margin * 2;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(17, 24, 39);
  doc.text("AI Remediation Report", margin, y);
  y += 16;

  const lines = report.split("\n");
  for (const raw of lines) {
    const line = raw.trimEnd();

    // Check remaining space
    const pageH = doc.internal.pageSize.getHeight();
    if (y > pageH - 60) {
      doc.addPage();
      y = 56;
    }

    if (line.startsWith("# ") && !line.startsWith("## ")) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.setTextColor(17, 24, 39);
      const wrapped = doc.splitTextToSize(line.slice(2), usableW);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 16 + 4;
    } else if (line.startsWith("## ")) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(31, 41, 55);
      const wrapped = doc.splitTextToSize(line.slice(3), usableW);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 14 + 6;
    } else if (line.startsWith("### ")) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9.5);
      doc.setTextColor(55, 65, 81);
      const wrapped = doc.splitTextToSize(line.slice(4), usableW);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 13 + 4;
    } else if (line.startsWith("#### ")) {
      doc.setFont("helvetica", "bolditalic");
      doc.setFontSize(9);
      doc.setTextColor(75, 85, 99);
      const wrapped = doc.splitTextToSize(line.slice(5), usableW);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 12 + 2;
    } else if (line.startsWith("- ") || line.startsWith("* ")) {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(17, 24, 39);
      const text = line.slice(2).replace(/\*\*(.+?)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1");
      const wrapped = doc.splitTextToSize(`• ${text}`, usableW - 12);
      doc.text(wrapped, margin + 10, y);
      y += wrapped.length * 11 + 2;
    } else if (line.startsWith("```")) {
      // skip fence markers
    } else if (line.trim() === "") {
      y += 5;
    } else {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(17, 24, 39);
      const text = line.replace(/\*\*(.+?)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1");
      const wrapped = doc.splitTextToSize(text, usableW);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 11 + 2;
    }
  }
  return y;
}

export function exportScanPdf(detail, options = {}) {
  const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 40;
  let y = margin;

  // ── Header ────────────────────────────────────────────────────────────────
  doc.setFillColor(17, 24, 39);
  doc.rect(0, 0, pageW, 56, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.setTextColor(255, 255, 255);
  doc.text("ChainFire", margin, 36);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(156, 163, 175);
  doc.text("Security Scan Report", margin, 50);

  y = 80;

  // ── Scan metadata ─────────────────────────────────────────────────────────
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(17, 24, 39);
  doc.text(detail.label || detail.target_url, margin, y);
  y += 18;

  const meta = [
    ["Target URL",  detail.target_url],
    ["Scan Mode",   detail.scan_mode === "semgrep_all" ? "Chained Scan" : "Custom Rules"],
    ["Status",      detail.status],
    ["Started",     fmt(detail.started_at)],
    ["Completed",   fmt(detail.completed_at)],
    ["Duration",    duration(detail.started_at, detail.completed_at)],
    ["Semgrep findings", String(detail.semgrep_findings?.length ?? 0)],
    ["Nuclei findings",  String(detail.nuclei_findings?.length ?? 0)],
  ];

  if (detail.nuclei_tags?.length) {
    meta.push(["Nuclei tags", detail.nuclei_tags.join(", ")]);
  }
  if (detail.error_message) {
    meta.push(["Warning", detail.error_message]);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    theme: "plain",
    styles: { fontSize: 9, cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: "bold", textColor: [75, 85, 99], cellWidth: 120 },
      1: { textColor: [17, 24, 39] },
    },
    body: meta,
  });

  y = doc.lastAutoTable.finalY + 24;

  // ── Semgrep findings ──────────────────────────────────────────────────────
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(17, 24, 39);
  doc.text(`Semgrep Findings (${detail.semgrep_findings?.length ?? 0})`, margin, y);
  y += 6;

  if (!detail.semgrep_findings?.length) {
    doc.setFont("helvetica", "italic");
    doc.setFontSize(9);
    doc.setTextColor(107, 114, 128);
    doc.text("No semgrep findings.", margin, y + 14);
    y += 28;
  } else {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["#", "Severity", "Rule ID", "Location", "Message"]],
      body: detail.semgrep_findings.map((f, i) => {
        const loc = f.location || {};
        const filePath = loc.file_path
          ? `${loc.file_path}${loc.line ? `:${loc.line}` : ""}`
          : "—";
        return [
          String(i + 1),
          (f.severity || "info").toUpperCase(),
          f.check_id || "—",
          filePath,
          f.message || "—",
        ];
      }),
      headStyles: { fillColor: [17, 24, 39], textColor: 255, fontSize: 8 },
      styles: { fontSize: 8, cellPadding: 4, overflow: "linebreak" },
      columnStyles: {
        0: { cellWidth: 24 },
        1: { cellWidth: 58 },
        2: { cellWidth: 120, font: "courier" },
        3: { cellWidth: 110, font: "courier" },
        4: { cellWidth: "auto" },
      },
      didParseCell(data) {
        if (data.column.index === 1 && data.section === "body") {
          const [r, g, b] = sevColor(data.cell.raw);
          data.cell.styles.textColor = [r, g, b];
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
    y = doc.lastAutoTable.finalY + 24;
  }

  // ── Nuclei findings ───────────────────────────────────────────────────────
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(17, 24, 39);
  doc.text(`Nuclei Findings (${detail.nuclei_findings?.length ?? 0})`, margin, y);
  y += 6;

  if (!detail.nuclei_findings?.length) {
    doc.setFont("helvetica", "italic");
    doc.setFontSize(9);
    doc.setTextColor(107, 114, 128);
    doc.text("No nuclei findings.", margin, y + 14);
    y += 28;
  } else {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["#", "Severity", "Template ID", "Name", "Matched At"]],
      body: detail.nuclei_findings.map((f, i) => {
        const info = f.info || {};
        return [
          String(i + 1),
          (info.severity || "info").toUpperCase(),
          f["template-id"] || "—",
          info.name || "—",
          f["matched-at"] || f.host || "—",
        ];
      }),
      headStyles: { fillColor: [17, 24, 39], textColor: 255, fontSize: 8 },
      styles: { fontSize: 8, cellPadding: 4, overflow: "linebreak" },
      columnStyles: {
        0: { cellWidth: 24 },
        1: { cellWidth: 58 },
        2: { cellWidth: 110, font: "courier" },
        3: { cellWidth: 120 },
        4: { cellWidth: "auto", font: "courier" },
      },
      didParseCell(data) {
        if (data.column.index === 1 && data.section === "body") {
          const [r, g, b] = sevColor(data.cell.raw);
          data.cell.styles.textColor = [r, g, b];
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
    y = doc.lastAutoTable.finalY + 24;
  }

  // ── AI Report ─────────────────────────────────────────────────────────────
  if (options.includeReport && detail.ai_report) {
    doc.addPage();
    y = 56;
    y = addReportSection(doc, detail.ai_report, margin, y, pageW);
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  const pageCount = doc.internal.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(156, 163, 175);
    doc.text(
      `ChainFire  •  Generated ${fmt(new Date().toISOString())}  •  Page ${p} of ${pageCount}`,
      margin,
      doc.internal.pageSize.getHeight() - 20
    );
  }

  const filename = `chainfire-${(detail.label || detail.id || "scan").replace(/\s+/g, "-").toLowerCase()}.pdf`;
  doc.save(filename);
}
