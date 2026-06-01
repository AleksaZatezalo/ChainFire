import React, { useCallback, useEffect, useState } from "react";
import { authApi } from "../api/client.js";

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric", month: "short", day: "numeric",
  });
}

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
