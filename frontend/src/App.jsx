import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import ScannerPage from "./pages/ScannerPage.jsx";
import SemgrepRulesPage from "./pages/SemgrepRulesPage.jsx";
import NucleiTemplatesPage from "./pages/NucleiTemplatesPage.jsx";
import WordlistsPage from "./pages/WordlistsPage.jsx";
import ResultsPage from "./pages/ResultsPage.jsx";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/scanner" replace />} />
        <Route path="/scanner" element={<ScannerPage />} />
        <Route path="/semgrep-rules" element={<SemgrepRulesPage />} />
        <Route path="/nuclei-templates" element={<NucleiTemplatesPage />} />
        <Route path="/wordlists" element={<WordlistsPage />} />
        <Route path="/results" element={<ResultsPage />} />
      </Routes>
    </Layout>
  );
}
