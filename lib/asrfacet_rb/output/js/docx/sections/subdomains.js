"use strict";

function buildSubdomains(data, helpers) {
  const subdomains = data.subdomains || [];
  const rows = subdomains.map((subdomain, index) =>
    helpers.dataRow([String(index + 1), subdomain])
  );

  return [
    helpers.heading2(`Discovered Subdomains (${subdomains.length})`),
    rows.length
      ? helpers.makeTable(["#", "Subdomain"], rows)
      : helpers.emptyState("No subdomains discovered."),
    helpers.hr(),
  ];
}

module.exports = buildSubdomains;
