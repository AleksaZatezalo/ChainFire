import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "../api/client.js";
import { useAuth } from "../context/AuthContext.jsx";

export default function LoginPage() {
  const { refresh } = useAuth();
  const navigate = useNavigate();

  const [form, setForm]         = useState({ username: "", password: "" });
  const [error, setError]       = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const set = (f) => (e) => setForm((p) => ({ ...p, [f]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!form.username || !form.password) {
      setError("Username and password are required.");
      return;
    }
    try {
      setSubmitting(true);
      await authApi.login({ username: form.username, password: form.password });
      await refresh();
      navigate("/");
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        "Login failed. Please check your credentials."
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <span className="auth-logo-icon">🔍</span>
          ChainFire
        </div>
        <h2 className="auth-title">Sign in</h2>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              className="form-control"
              type="text"
              autoComplete="username"
              autoFocus
              value={form.username}
              onChange={set("username")}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              className="form-control"
              type="password"
              autoComplete="current-password"
              value={form.password}
              onChange={set("password")}
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: 4 }}
            disabled={submitting}
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/forgot-password">Forgot password?</Link>
          <span className="auth-link-sep">·</span>
          <Link to="/register">Create account</Link>
        </div>
      </div>
    </div>
  );
}
