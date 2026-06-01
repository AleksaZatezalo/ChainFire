import React from "react";
import ResourceManager from "../components/ResourceManager.jsx";
import { nucleiTemplatesApi } from "../api/client.js";

const DEFAULT_TEMPLATE = `id: my-custom-template

info:
  name: My Custom Template
  author: dast-tool
  severity: medium
  description: Checks for a custom vulnerability pattern
  tags: custom,dast

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/test"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "vulnerable_indicator"
        part: body
`;

export default function NucleiTemplatesPage() {
  return (
    <ResourceManager
      title="Nuclei Templates"
      description="Custom YAML nuclei templates used for DAST scanning. Selected templates are passed directly to nuclei during a scan."
      apiClient={nucleiTemplatesApi}
      defaultContent={DEFAULT_TEMPLATE}
      contentLabel="YAML Template Content"
    />
  );
}
