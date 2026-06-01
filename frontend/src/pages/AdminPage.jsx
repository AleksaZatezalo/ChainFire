import React, { useCallback, useEffect, useState } from "react";
import { authApi, apiKeysApi } from "../api/client.js";

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric", month: "short", day: "numeric",
  });
}

// ── API Key section ────────────────────────────────────────────────────────────
function ApiKeySection() {
  const [keys, setKeys]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm]         = useState({ label: "", provider: "anthropic", key_value: "" });
  const [editId, setEditId]     = useState(null);
  const [editForm, setEditForm] = useState({ label: "", key_value: "" });
  const [error, setError]       = useState(null);
  const [saving, setSaving]     = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiKeysApi.list();
      setKeys(res.data);
    } catch { setError("Failed to load API keys."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!form.label || !form.key_value) { setError("Label and key are required."); return; }
    try {
      setSaving(true); setError(null);
      await apiKeysApi.create(form);
      setForm({ label: "", provider: "anthropic", key_value: "" });
      setShowForm(false);
      load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to save key.");
    } finally { setSaving(false); }
  };

  const handleUpdate = async (id) => {
    if (!editForm.label && !editForm.key_value) return;
    try {
      setSaving(true); setError(null);
      const payload = {};
      if (editForm.label)     payload.label     = editForm.label;
      if (editForm.key_value) payload.key_value = editForm.key_value;
      await apiKeysApi.update(id, payload);
      setEditId(null);
      load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to update key.");
    } finally { setSaving(false); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this API key?")) return;
    try { await apiKeysApi.delete(id); load(); }
    catch { setError("Failed to delete key."); }
  };

  const startEdit = (key) => {
    setEditId(key.id);
    setEditForm({ label: key.label, key_value: "" });
  };

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>API Keys</span>
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm((v) => !v)}>
          {showForm ? "✕ Cancel" : "+ Add Key"}
        </button>
      </div>

      {error && <div className="alert alert-error" style={{ margin: "12px 16px 0" }}>{error}</div>}

      {showForm && (
        <form onSubmit={handleCreate} style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
          <div className="form-group">
            <label className="form-label">Label</label>
            <input className="form-control" placeholder="e.g. Claude API key" value={form.label}
              onChange={(e) => setForm((p) => ({ ...p, label: e.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label">Provider</label>
            <select className="form-control" value={form.provider}
              onChange={(e) => setForm((p) => ({ ...p, provider: e.target.value }))}>
              <option value="anthropic">Anthropic (Claude)</option>
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">API Key</label>
            <input className="form-control" type="password" placeholder="sk-ant-api-..." value={form.key_value}
              onChange={(e) => setForm((p) => ({ ...p, key_value: e.target.value }))} />
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 16, gap: 8 }}>
            <button type="submit" className="btn btn-primary btn-sm" disabled={saving}>
              {saving ? "Saving…" : "Save Key"}
            </button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="loading-state" style={{ padding: 24 }}><div className="spinner" /></div>
      ) : keys.length === 0 ? (
        <div className="empty-state" style={{ padding: 32 }}>
          <p className="empty-state-body">No API keys configured. Add a key to enable exploit generation.</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr><th>Label</th><th>Provider</th><th>Key</th><th>Updated</th><th /></tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <React.Fragment key={k.id}>
                  <tr>
                    <td style={{ fontWeight: 500 }}>{k.label}</td>
                    <td className="text-muted text-sm">Anthropic</td>
                    <td className="font-mono text-sm" style={{ color: "var(--text-muted)" }}>{k.masked_key}</td>
                    <td className="text-muted text-sm">{formatDate(k.updated_at)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => startEdit(k)}>Edit</button>
                        <button className="btn btn-danger btn-sm" onClick={() => handleDelete(k.id)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                  {editId === k.id && (
                    <tr>
                      <td colSpan={5} style={{ padding: "0 14px 12px" }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "flex-end", flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 140 }}>
                            <label className="form-label" style={{ fontSize: 11 }}>Label</label>
                            <input className="form-control" value={editForm.label}
                              onChange={(e) => setEditForm((p) => ({ ...p, label: e.target.value }))} />
                          </div>
                          <div style={{ flex: 2, minWidth: 200 }}>
                            <label className="form-label" style={{ fontSize: 11 }}>New Key Value (leave blank to keep current)</label>
                            <input className="form-control" type="password" placeholder="sk-ant-api-..."
                              value={editForm.key_value}
                              onChange={(e) => setEditForm((p) => ({ ...p, key_value: e.target.value }))} />
                          </div>
                          <button className="btn btn-primary btn-sm" disabled={saving} onClick={() => handleUpdate(k.id)}>
                            {saving ? "Saving…" : "Save"}
                          </button>
                          <button className="btn btn-secondary btn-sm" onClick={() => setEditId(null)}>Cancel</button>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main admin page ────────────────────────────────────────────────────────────
export default function AdminPage() {
  const [users, setUsers]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [busy, setBusy]       = useState({});

  const load = useCallback(async () => {
    try {
      const res = await authApi.listUsers();
      setUsers(res.data);
      setError(null);
    } catch {
      setError("Failed to load users.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const withBusy = (id, fn) => async () => {
    setBusy((p) => ({ ...p, [id]: true }));
    try { await fn(); await load(); }
    catch (err) { alert(err?.response?.data?.detail || "Action failed."); }
    finally { setBusy((p) => ({ ...p, [id]: false })); }
  };

  const handleApprove = (id) => withBusy(id, () => authApi.approveUser(id));
  const handleRevoke  = (id) => withBusy(id, () => authApi.revokeUser(id));
  const handleDelete  = (id) => withBusy(id, async () => {
    if (!window.confirm("Delete this user permanently?")) return;
    await authApi.deleteUser(id);
  });

  const pending  = users.filter((u) => !u.is_staff && !u.is_approved);
  const approved = users.filter((u) => !u.is_staff && u.is_approved);
  const admins   = users.filter((u) => u.is_staff);

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Admin Panel</h1>
          <p className="page-subtitle">{users.length} user{users.length !== 1 ? "s" : ""} total</p>
        </div>
        <button className="btn btn-secondary" onClick={load}>↺ Refresh</button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading-state"><div className="spinner" /> Loading…</div>}

      {/* ── Pending approval ─────────────────────────────────────────────── */}
      {pending.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)" }}>
            <span style={{ fontWeight: 600, fontSize: 13 }}>
              Pending Approval
            </span>
            <span className="badge badge-warning" style={{ marginLeft: 8 }}>
              {pending.length}
            </span>
          </div>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Registered</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {pending.map((u) => (
                  <tr key={u.id}>
                    <td style={{ fontWeight: 500 }}>{u.username}</td>
                    <td className="text-muted text-sm">{formatDate(u.date_joined)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          className="btn btn-primary btn-sm"
                          disabled={busy[u.id]}
                          onClick={handleApprove(u.id)}
                        >
                          Approve
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          disabled={busy[u.id]}
                          onClick={handleDelete(u.id)}
                        >
                          Reject
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

      {/* ── Approved users ────────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)" }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Approved Users</span>
        </div>
        {approved.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-body">No approved non-admin users yet.</p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Registered</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {approved.map((u) => (
                  <tr key={u.id}>
                    <td style={{ fontWeight: 500 }}>{u.username}</td>
                    <td className="text-muted text-sm">{formatDate(u.date_joined)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={busy[u.id]}
                          onClick={handleRevoke(u.id)}
                        >
                          Revoke
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          disabled={busy[u.id]}
                          onClick={handleDelete(u.id)}
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
        )}
      </div>

      {/* ── API Keys ─────────────────────────────────────────────────────── */}
      <ApiKeySection />

      {/* ── Admins ───────────────────────────────────────────────────────── */}
      <div className="card">
        <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)" }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Administrators</span>
        </div>
        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Registered</th>
              </tr>
            </thead>
            <tbody>
              {admins.map((u) => (
                <tr key={u.id}>
                  <td style={{ fontWeight: 500 }}>
                    {u.username}
                    <span className="badge badge-info" style={{ marginLeft: 8 }}>admin</span>
                  </td>
                  <td className="text-muted text-sm">{formatDate(u.date_joined)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
