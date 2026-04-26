"use strict";

const { sevColor } = require("../../shared/colors");

function buildFindings(data, helpers) {
  const findings = data.findings || [];
  const elements = [
    helpers.heading2(`Security Findings (${findings.length})`),
  ];

  if (!findings.length) {
    elements.push(helpers.emptyState("No findings recorded."));
    elements.push(helpers.hr());
    return elements;
  }

  findings.forEach((finding, index) => {
    const severity = finding.severity || "informational";
    elements.push(
      helpers.heading3(`${index + 1}. ${finding.title || "Untitled Finding"}`),
      helpers.para(`Severity: ${severity}`, {
        color: sevColor(severity),
        bold: true,
      }),
      helpers.labelValue("Asset", finding.asset || "-")
    );
    if (finding.description) {
      elements.push(helpers.para(finding.description));
    }
    elements.push(helpers.para(""));
  });

  elements.push(helpers.hr());
  return elements;
}

module.exports = buildFindings;
