import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import Layout from "./components/Layout.jsx";
import ScannerPage from "./pages/ScannerPage.jsx";
import SemgrepRulesPage from "./pages/SemgrepRulesPage.jsx";
import NucleiTemplatesPage from "./pages/NucleiTemplatesPage.jsx";
import WordlistsPage from "./pages/WordlistsPage.jsx";
import ResultsPage from "./pages/ResultsPage.jsx";
import ScheduledScansPage from "./pages/ScheduledScansPage.jsx";
import AdminPage from "./pages/AdminPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import ForgotPasswordPage from "./pages/ForgotPasswordPage.jsx";

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "var(--bg-app)" }}>
        <div className="loading-state"><div className="spinner" /></div>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;

  if (!user.is_approved) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "var(--bg-app)" }}>
        <div className="auth-card" style={{ textAlign: "center" }}>
          <div className="auth-logo"><span className="auth-logo-icon">🔍</span>ChainFire</div>
          <p style={{ marginTop: 16, color: "var(--text-muted)" }}>
            Your account is pending admin approval.
          </p>
        </div>
      </div>
    );
  }

  if (adminOnly && !user.is_staff) return <Navigate to="/" replace />;

  return children;
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user && user.is_approved) return <Navigate to="/" replace />;
  return children;
}

function AppRoutes() {
  return (
    <Routes>
      {/* Public auth routes */}
      <Route path="/login"           element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/register"        element={<PublicRoute><RegisterPage /></PublicRoute>} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />

      {/* Protected app routes */}
      <Route path="/*" element={
        <ProtectedRoute>
          <Layout>
            <Routes>
              <Route path="/"                  element={<Navigate to="/scanner" replace />} />
              <Route path="/scanner"           element={<ScannerPage />} />
              <Route path="/results"           element={<ResultsPage />} />
              <Route path="/scheduled-scans"   element={<ScheduledScansPage />} />
              <Route path="/semgrep-rules"     element={<SemgrepRulesPage />} />
              <Route path="/nuclei-templates"  element={<NucleiTemplatesPage />} />
              <Route path="/wordlists"         element={<WordlistsPage />} />
              <Route path="/admin"             element={
                <ProtectedRoute adminOnly>
                  <AdminPage />
                </ProtectedRoute>
              } />
            </Routes>
          </Layout>
        </ProtectedRoute>
      } />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
