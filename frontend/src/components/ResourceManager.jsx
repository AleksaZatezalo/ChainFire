/**
 * Generic CRUD manager for semgrep rules and nuclei templates.
 * Both resources share identical UI structure — list + YAML editor modal.
 */
import React, { useState, useEffect, useCallback } from "react";

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ResourceManager({
  title,
  description,
  apiClient,
  defaultContent,
  contentLabel = "YAML Content",
}) {
  const [items, setItems]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [editing, setEditing]   = useState(null); // null | {} (new) | item (existing)
  const [saving, setSaving]     = useState(false);
  const [saveError, setSaveError] = useState(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiClient.list();
      setItems(res.data);
    } catch {
      setError("Failed to load items. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { load(); }, [load]);

  const openNew = () => setEditing({ name: "", content: defaultContent });
  const openEdit = (item) => setEditing({ ...item });
  const closeModal = () => { setEditing(null); setSaveError(null); };

  const handleSave = async () => {
    if (!editing.name.trim()) {
      setSaveError("Name is required.");
      return;
    }
    if (!editing.content.trim()) {
      setSaveError("Content cannot be empty.");
      return;
    }
    try {
      setSaving(true);
      setSaveError(null);
      if (editing.id) {
        await apiClient.update(editing.id, {
          name: editing.name,
          content: editing.content,
        });
      } else {
        await apiClient.create({ name: editing.name, content: editing.content });
      }
      await load();
      closeModal();
    } catch (err) {
      const msg =
        err?.response?.data?.name?.[0] ||
        err?.response?.data?.detail ||
        "Save failed.";
      setSaveError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (item) => {
    if (!window.confirm(`Delete "${item.name}"? This cannot be undone.`)) return;
    try {
      await apiClient.delete(item.id);
      setItems((prev) => prev.filter((i) => i.id !== item.id));
    } catch {
      alert("Delete failed.");
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">{title}</h1>
          {description && <p className="page-subtitle">{description}</p>}
        </div>
        <button className="btn btn-primary" onClick={openNew}>
          + New
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        {loading ? (
          <div className="loading-state">
            <div className="spinner" />
            Loading…
          </div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon">📄</span>
            <p className="empty-state-title">No {title.toLowerCase()} yet</p>
            <p className="empty-state-body">
              Click <strong>+ New</strong> to create your first one.
            </p>
          </div>
        ) : (
          items.map((item) => (
            <div key={item.id} className="resource-list-item">
              <div className="resource-item-info">
                <div className="resource-item-name">{item.name}</div>
                <div className="resource-item-meta">
                  Updated {formatDate(item.updated_at)}
                </div>
              </div>
              <div className="resource-item-actions">
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => openEdit(item)}
                >
                  Edit
                </button>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={() => handleDelete(item)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {editing && (
        <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && closeModal()}>
          <div className="modal">
            <div className="modal-header">
              <span className="modal-title">
                {editing.id ? `Edit: ${editing.name}` : `New ${title.replace(/s$/, "")}`}
              </span>
              <button className="modal-close" onClick={closeModal}>×</button>
            </div>

            <div className="modal-body">
              {saveError && <div className="alert alert-error">{saveError}</div>}

              <div className="form-group">
                <label className="form-label">Name</label>
                <input
                  className="form-control"
                  type="text"
                  placeholder="e.g. sql-injection-rule"
                  value={editing.name}
                  onChange={(e) =>
                    setEditing((prev) => ({ ...prev, name: e.target.value }))
                  }
                />
              </div>

              <div className="form-group">
                <label className="form-label">{contentLabel}</label>
                <textarea
                  className="form-control"
                  value={editing.content}
                  onChange={(e) =>
                    setEditing((prev) => ({ ...prev, content: e.target.value }))
                  }
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closeModal}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleSave}
                disabled={saving}
              >
                {saving ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
