"use strict";

function JsEndpointsPage({ data, helpers }) {
  const { React, Page, Text, AccentBar, TableComp, Footer, S } = helpers;
  const endpoints = data.js_endpoints || [];
  const rows = endpoints.map((endpoint, index) => [String(index + 1), endpoint]);

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, `JS Endpoints (${endpoints.length})`),
    rows.length
      ? React.createElement(TableComp, { headers: ["#", "Endpoint"], rows })
      : React.createElement(Text, { style: S.emptyState }, "No JS endpoints discovered."),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = JsEndpointsPage;
