import React, { useState, useEffect, useCallback } from "react";
import { wordlistsApi } from "../api/client.js";

const DEFAULT_CONTENT = `/api/v1/users
/api/v1/users/1
/api/v1/admin
/api/v1/login
/api/v1/register
/api/v1/reset-password
/api/v1/products
/api/v1/orders
# Lines starting with # are comments and will be ignored
`;

function countPaths(content) {
  return (content || "")
    .split("\n")
    .filter((l) => l.trim() && !l.trim().startsWith("#")).length;
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function WordlistsPage() {
  const [items, setItems]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [editing, setEditing]   = useState(null);
  const [saving, setSaving]     = useState(false);
  const [saveError, setSaveError] = useState(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await wordlistsApi.list();
      setItems(res.data);
    } catch {
      setError("Failed to load wordlists. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openNew  = () => setEditing({ name: "", content: DEFAULT_CONTENT });
  const openEdit = (item) => setEditing({ ...item });
  const close    = () => { setEditing(null); setSaveError(null); };

  const handleSave = async () => {
    if (!editing.name.trim()) { setSaveError("Name is required."); return; }
    try {
      setSaving(true);
      setSaveError(null);
      if (editing.id) {
        await wordlistsApi.update(editing.id, { name: editing.name, content: editing.content });
      } else {
        await wordlistsApi.create({ name: editing.name, content: editing.content });
      }
      await load();
      close();
    } catch (err) {
      setSaveError(
        err?.response?.data?.name?.[0] ||
        err?.response?.data?.detail ||
        "Save failed."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (item) => {
    if (!window.confirm(`Delete "${item.name}"?`)) return;
    try {
      await wordlistsApi.delete(item.id);
      setItems((prev) => prev.filter((i) => i.id !== item.id));
    } catch {
      alert("Delete failed.");
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Wordlists</h1>
          <p className="page-subtitle">
            Lists of API paths to test. Combined with the target URL to build the full target list for nuclei.
          </p>
        </div>
        <button className="btn btn-primary" onClick={openNew}>+ New</button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        {loading ? (
          <div className="loading-state"><div className="spinner" /> Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon">📂</span>
            <p className="empty-state-title">No wordlists yet</p>
            <p className="empty-state-body">Click <strong>+ New</strong> to create one.</p>
          </div>
        ) : (
          items.map((item) => (
            <div key={item.id} className="resource-list-item">
              <div className="resource-item-info">
                <div className="resource-item-name">{item.name}</div>
                <div className="resource-item-meta">
                  {countPaths(item.content)} paths · Updated {formatDate(item.updated_at)}
                </div>
              </div>
              <div className="resource-item-actions">
                <button className="btn btn-secondary btn-sm" onClick={() => openEdit(item)}>Edit</button>
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(item)}>Delete</button>
              </div>
            </div>
          ))
        )}
      </div>

      {editing && (
        <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && close()}>
          <div className="modal" style={{ maxWidth: 680 }}>
            <div className="modal-header">
              <span className="modal-title">
                {editing.id ? `Edit: ${editing.name}` : "New Wordlist"}
              </span>
              <button className="modal-close" onClick={close}>×</button>
            </div>

            <div className="modal-body">
              {saveError && <div className="alert alert-error">{saveError}</div>}

              <div className="form-group">
                <label className="form-label">Name</label>
                <input
                  className="form-control"
                  type="text"
                  placeholder="e.g. api-v1-endpoints"
                  value={editing.name}
                  onChange={(e) => setEditing((p) => ({ ...p, name: e.target.value }))}
                />
              </div>

              <div className="form-group">
                <label className="form-label">
                  Paths&nbsp;
                  <span className="text-muted">
                    ({countPaths(editing.content)} paths)
                  </span>
                </label>
                <textarea
                  className="form-control"
                  placeholder="/api/v1/users&#10;/api/v1/admin&#10;# comment"
                  value={editing.content}
                  onChange={(e) => setEditing((p) => ({ ...p, content: e.target.value }))}
                  style={{ minHeight: 380 }}
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={close}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
