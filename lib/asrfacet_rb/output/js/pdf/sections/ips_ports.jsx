"use strict";

function IpsPortsPage({ data, helpers }) {
  const { React, Page, Text, AccentBar, TableComp, Footer, S } = helpers;
  const rows = [];
  Object.entries(data.ports || {}).forEach(([ip, ports]) => {
    ports.forEach((port) => {
      rows.push([ip, String(port.port), port.service || "-", port.banner || "-"]);
    });
  });

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, `IPs and Open Ports (${(data.ips || []).length} IPs)`),
    rows.length
      ? React.createElement(TableComp, {
          headers: ["IP", "Port", "Service", "Banner"],
          rows,
        })
      : React.createElement(Text, { style: S.emptyState }, "No port data available."),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = IpsPortsPage;
