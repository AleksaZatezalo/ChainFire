import axios from "axios";

function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
  return match ? match[1] : "";
}

const http = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});

// Attach CSRF token to every mutating request
http.interceptors.request.use((config) => {
  if (!["get", "head", "options"].includes(config.method)) {
    config.headers["X-CSRFToken"] = getCsrfToken();
  }
  return config;
});

// ── Auth ───────────────────────────────────────────────────────────────────────
export const authApi = {
  csrf:             ()       => http.get("/auth/csrf/"),
  me:               ()       => http.get("/auth/me/"),
  register:         (data)   => http.post("/auth/register/", data),
  login:            (data)   => http.post("/auth/login/", data),
  logout:           ()       => http.post("/auth/logout/"),
  securityQuestion: (data)   => http.post("/auth/security-question/", data),
  resetPassword:    (data)   => http.post("/auth/reset-password/", data),
  // Admin
  listUsers:    ()         => http.get("/auth/users/"),
  approveUser:  (id)       => http.post(`/auth/users/${id}/approve/`),
  revokeUser:   (id)       => http.post(`/auth/users/${id}/revoke/`),
  deleteUser:   (id)       => http.delete(`/auth/users/${id}/`),
};

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
  list:   ()     => http.get("/scans/"),
  get:    (id)   => http.get(`/scans/${id}/`),
  create: (data) => http.post("/scans/", data),
  delete: (id)   => http.delete(`/scans/${id}/`),
};

// ── Exploit generation ────────────────────────────────────────────────────────
export const exploitsApi = {
  list:     ()                    => http.get("/exploits/"),
  get:      (id)                  => http.get(`/exploits/${id}/`),
  delete:   (id)                  => http.delete(`/exploits/${id}/`),
  generate: (scanId, findingIndex) =>
    http.post(`/scans/${scanId}/generate-exploit/`, { finding_index: findingIndex }),
};

// ── API Keys (admin) ──────────────────────────────────────────────────────────
export const apiKeysApi = {
  list:   ()         => http.get("/auth/api-keys/"),
  create: (data)     => http.post("/auth/api-keys/", data),
  update: (id, data) => http.patch(`/auth/api-keys/${id}/`, data),
  delete: (id)       => http.delete(`/auth/api-keys/${id}/`),
};

// ── Scheduled Scans ───────────────────────────────────────────────────────────
export const scheduledScansApi = {
  list:   ()         => http.get("/scheduled-scans/"),
  get:    (id)       => http.get(`/scheduled-scans/${id}/`),
  create: (data)     => http.post("/scheduled-scans/", data),
  update: (id, data) => http.put(`/scheduled-scans/${id}/`, data),
  delete: (id)       => http.delete(`/scheduled-scans/${id}/`),
  toggle: (id)       => http.post(`/scheduled-scans/${id}/toggle/`),
};

// ── Health ─────────────────────────────────────────────────────────────────────
export const healthApi = {
  check: () => http.get("/health/"),
};
