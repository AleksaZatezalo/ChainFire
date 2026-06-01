import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "../api/client.js";
import { useAuth } from "../context/AuthContext.jsx";

const SECURITY_QUESTIONS = [
  { value: "pet",    label: "What was the name of your first pet?" },
  { value: "city",   label: "What city were you born in?" },
  { value: "school", label: "What was the name of your primary school?" },
  { value: "mother", label: "What is your mother's maiden name?" },
  { value: "street", label: "What street did you grow up on?" },
  { value: "car",    label: "What was the make of your first car?" },
];

export default function RegisterPage() {
  const { refresh } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({
    username:          "",
    password:          "",
    security_question: "pet",
    security_answer:   "",
  });
  const [error, setError]       = useState(null);
  const [pending, setPending]   = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const set = (f) => (e) => setForm((p) => ({ ...p, [f]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    const { username, password, security_question, security_answer } = form;
    if (!username || !password || !security_answer) {
      setError("All fields are required.");
      return;
    }
    try {
      setSubmitting(true);
      const res = await authApi.register({ username, password, security_question, security_answer });
      if (res.data.pending) {
        setPending(true);
      } else {
        // First user — auto logged in
        await refresh();
        navigate("/");
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Registration failed.");
    } finally {
      setSubmitting(false);
    }
  };

  if (pending) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-logo">
            <span className="auth-logo-icon">🔍</span>
            ChainFire
          </div>
          <div className="alert alert-success" style={{ marginTop: 8 }}>
            <strong>Registration submitted!</strong> Your account is awaiting admin
            approval. You will be able to sign in once approved.
          </div>
          <div className="auth-links">
            <Link to="/login">Back to sign in</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <span className="auth-logo-icon">🔍</span>
          ChainFire
        </div>
        <h2 className="auth-title">Create account</h2>
        <p className="auth-subtitle">
          The first account becomes administrator.
        </p>

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
              autoComplete="new-password"
              value={form.password}
              onChange={set("password")}
            />
            <p style={{ color: "var(--text-muted)", fontSize: 12, marginTop: 4 }}>
              Minimum 6 characters.
            </p>
          </div>
          <div className="form-group">
            <label className="form-label">Security question</label>
            <select
              className="form-control"
              value={form.security_question}
              onChange={set("security_question")}
            >
              {SECURITY_QUESTIONS.map((q) => (
                <option key={q.value} value={q.value}>{q.label}</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Answer</label>
            <input
              className="form-control"
              type="text"
              autoComplete="off"
              placeholder="Your answer (case-insensitive)"
              value={form.security_answer}
              onChange={set("security_answer")}
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: 4 }}
            disabled={submitting}
          >
            {submitting ? "Creating account…" : "Create account"}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/login">Already have an account? Sign in</Link>
        </div>
      </div>
    </div>
  );
}
