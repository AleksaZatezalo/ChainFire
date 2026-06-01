import React from "react";
import ResourceManager from "../components/ResourceManager.jsx";
import { semgrepRulesApi } from "../api/client.js";

const DEFAULT_RULE = `rules:
  - id: my-custom-rule
    patterns:
      - pattern: |
          exec($CMD)
    message: "Potential command injection via exec()"
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-78"
`;

export default function SemgrepRulesPage() {
  return (
    <ResourceManager
      title="Semgrep Rules"
      description="Custom YAML rules used for SAST scanning. Selected rules are applied when a source code path is provided in the scanner."
      apiClient={semgrepRulesApi}
      defaultContent={DEFAULT_RULE}
      contentLabel="YAML Rule Content"
    />
  );
}
