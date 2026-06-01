import axios from "axios";

const http = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

// ── Semgrep Rules ──────────────────────────────────────────────────────────────
export const semgrepRulesApi = {
  list:   ()         => http.get("/semgrep-rules/"),
  get:    (id)       => http.get(`/semgrep-rules/${id}/`),
  create: (data)     => http.post("/semgrep-rules/", data),
  update: (id, data) => http.put(`/semgrep-rules/${id}/`, data),
  delete: (id)       => http.delete(`/semgrep-rules/${id}/`),
};

// ── Nuclei Templates ───────────────────────────────────────────────────────────
export const nucleiTemplatesApi = {
  list:   ()         => http.get("/nuclei-templates/"),
  get:    (id)       => http.get(`/nuclei-templates/${id}/`),
  create: (data)     => http.post("/nuclei-templates/", data),
  update: (id, data) => http.put(`/nuclei-templates/${id}/`, data),
  delete: (id)       => http.delete(`/nuclei-templates/${id}/`),
};

// ── Wordlists ──────────────────────────────────────────────────────────────────
export const wordlistsApi = {
  list:   ()         => http.get("/wordlists/"),
  get:    (id)       => http.get(`/wordlists/${id}/`),
  create: (data)     => http.post("/wordlists/", data),
  update: (id, data) => http.put(`/wordlists/${id}/`, data),
  delete: (id)       => http.delete(`/wordlists/${id}/`),
};

// ── Scans ──────────────────────────────────────────────────────────────────────
export const scansApi = {
  list:   ()         => http.get("/scans/"),
  get:    (id)       => http.get(`/scans/${id}/`),
  create: (data)     => http.post("/scans/", data),
  delete: (id)       => http.delete(`/scans/${id}/`),
};

// ── Health ─────────────────────────────────────────────────────────────────────
export const healthApi = {
  check: () => http.get("/health/"),
};
