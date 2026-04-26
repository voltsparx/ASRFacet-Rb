"use strict";

function buildSummary(data, helpers) {
  const stats = data.stats || {};
  const portCount = Object.values(data.ports || {}).reduce(
    (memo, entries) => memo + entries.length,
    0
  );

  return [
    helpers.heading2("Executive Summary"),
    helpers.makeTable(["Metric", "Value"], [
      helpers.dataRow(["Subdomains Found", String(stats.subdomains || 0)]),
      helpers.dataRow(["IPs Identified", String(stats.ips || 0)]),
      helpers.dataRow(["Security Findings", String(stats.findings || 0)]),
      helpers.dataRow(["JS Endpoints", String(stats.js_endpoints || 0)]),
      helpers.dataRow(["Open Ports", String(portCount)]),
      helpers.dataRow(["Errors", String(stats.errors || 0)]),
    ]),
    helpers.hr(),
  ];
}

module.exports = buildSummary;
