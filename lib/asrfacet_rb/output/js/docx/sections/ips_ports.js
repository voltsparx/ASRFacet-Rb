"use strict";

function buildIpsPorts(data, helpers) {
  const rows = [];
  Object.entries(data.ports || {}).forEach(([ip, ports]) => {
    ports.forEach((port) => {
      rows.push(
        helpers.dataRow([
          ip,
          String(port.port),
          port.service || "-",
          port.banner || "-",
        ])
      );
    });
  });

  return [
    helpers.heading2(`IPs and Open Ports (${(data.ips || []).length} IPs)`),
    rows.length
      ? helpers.makeTable(["IP", "Port", "Service", "Banner"], rows)
      : helpers.emptyState("No port data available."),
    helpers.hr(),
  ];
}

module.exports = buildIpsPorts;
