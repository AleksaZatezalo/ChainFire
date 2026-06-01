import React from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

const NAV_ITEMS = [
  { to: "/results",          icon: "📋", label: "Results" },
  { to: "/scanner",          icon: "▶",  label: "Scanner" },
  { to: "/scheduled-scans",  icon: "🕐", label: "Scheduled Scans" },
  { to: "/semgrep-rules",    icon: "📝", label: "Semgrep Rules" },
  { to: "/nuclei-templates", icon: "🧬", label: "Nuclei Templates" },
  { to: "/wordlists",        icon: "📂", label: "Wordlists" },
  { to: "/exploits",         icon: "⚡", label: "Exploits" },
];

export default function Layout({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="sidebar-logo-icon">🔍</span>
          ChainFire
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `nav-item${isActive ? " active" : ""}`
              }
            >
              <span className="nav-item-icon">{icon}</span>
              {label}
            </NavLink>
          ))}

          {user?.is_staff && (
            <NavLink
              to="/admin"
              className={({ isActive }) =>
                `nav-item${isActive ? " active" : ""}`
              }
            >
              <span className="nav-item-icon">⚙️</span>
              Admin
            </NavLink>
          )}
        </nav>

        {user && (
          <div className="sidebar-user">
            <div className="sidebar-user-info">
              <span className="sidebar-user-name">{user.username}</span>
              {user.is_staff && (
                <span className="badge badge-info" style={{ fontSize: 10 }}>admin</span>
              )}
            </div>
            <button className="sidebar-logout-btn" onClick={handleLogout} title="Sign out">
              ↪
            </button>
          </div>
        )}
      </aside>

      <main className="main-content">{children}</main>
    </div>
  );
}
