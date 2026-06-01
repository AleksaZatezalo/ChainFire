import React from "react";
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/scanner",          icon: "▶",  label: "Scanner" },
  { to: "/results",          icon: "📋", label: "Results" },
  { to: "/semgrep-rules",    icon: "📝", label: "Semgrep Rules" },
  { to: "/nuclei-templates", icon: "🧬", label: "Nuclei Templates" },
  { to: "/wordlists",        icon: "📂", label: "Wordlists" },
];

export default function Layout({ children }) {
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
        </nav>
      </aside>

      <main className="main-content">{children}</main>
    </div>
  );
}
