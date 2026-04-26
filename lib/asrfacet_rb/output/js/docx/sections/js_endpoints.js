"use strict";

function buildJsEndpoints(data, helpers) {
  const endpoints = data.js_endpoints || [];
  const rows = endpoints.map((endpoint, index) =>
    helpers.dataRow([String(index + 1), endpoint])
  );

  return [
    helpers.heading2(`JS Endpoints (${endpoints.length})`),
    rows.length
      ? helpers.makeTable(["#", "Endpoint"], rows)
      : helpers.emptyState("No JS endpoints discovered."),
    helpers.hr(),
  ];
}

module.exports = buildJsEndpoints;
