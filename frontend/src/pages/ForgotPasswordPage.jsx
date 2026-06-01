import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "../api/client.js";

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [step, setStep]                     = useState(1); // 1 = username, 2 = answer + new password
  const [username, setUsername]             = useState("");
  const [questionLabel, setQuestionLabel]   = useState("");
  const [questionKey, setQuestionKey]       = useState("");
  const [answer, setAnswer]                 = useState("");
  const [newPassword, setNewPassword]       = useState("");
  const [error, setError]                   = useState(null);
  const [submitting, setSubmitting]         = useState(false);
  const [done, setDone]                     = useState(false);

  const handleFindUser = async (e) => {
    e.preventDefault();
    setError(null);
    if (!username.trim()) { setError("Username is required."); return; }
    try {
      setSubmitting(true);
      const res = await authApi.securityQuestion({ username: username.trim() });
      setQuestionLabel(res.data.security_question_label);
      setQuestionKey(res.data.security_question);
      setStep(2);
    } catch (err) {
      setError(err?.response?.data?.detail || "User not found.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = async (e) => {
    e.preventDefault();
    setError(null);
    if (!answer.trim() || !newPassword) { setError("All fields are required."); return; }
    try {
      setSubmitting(true);
      await authApi.resetPassword({
        username: username.trim(),
        security_answer: answer.trim(),
        new_password: newPassword,
      });
      setDone(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Reset failed. Check your answer.");
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-logo"><span className="auth-logo-icon">🔍</span>ChainFire</div>
          <div className="alert alert-success" style={{ marginTop: 8 }}>
            Password reset successfully. You can now sign in with your new password.
          </div>
          <div className="auth-links">
            <Link to="/login">Sign in</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo"><span className="auth-logo-icon">🔍</span>ChainFire</div>
        <h2 className="auth-title">Reset password</h2>

        {error && <div className="alert alert-error">{error}</div>}

        {step === 1 && (
          <form onSubmit={handleFindUser}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                className="form-control"
                type="text"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: "100%", marginTop: 4 }}
              disabled={submitting}
            >
              {submitting ? "Looking up…" : "Continue"}
            </button>
          </form>
        )}

        {step === 2 && (
          <form onSubmit={handleReset}>
            <div className="form-group">
              <label className="form-label">Security question</label>
              <p style={{ fontSize: 13, marginTop: 2, color: "var(--text)" }}>
                {questionLabel}
              </p>
            </div>
            <div className="form-group">
              <label className="form-label">Your answer</label>
              <input
                className="form-control"
                type="text"
                autoFocus
                autoComplete="off"
                placeholder="Case-insensitive"
                value={answer}
                onChange={(e) => setAnswer(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">New password</label>
              <input
                className="form-control"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: "100%", marginTop: 4 }}
              disabled={submitting}
            >
              {submitting ? "Resetting…" : "Reset password"}
            </button>
          </form>
        )}

        <div className="auth-links">
          <Link to="/login">Back to sign in</Link>
        </div>
      </div>
    </div>
  );
}
