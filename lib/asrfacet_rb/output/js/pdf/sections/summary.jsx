"use strict";

function SummaryPage({ data, helpers }) {
  const { React, Page, Text, View, AccentBar, StatCard, Footer, S, COLORS } = helpers;
  const stats = data.stats || {};
  const portCount = Object.values(data.ports || {}).reduce(
    (memo, entries) => memo + entries.length,
    0
  );

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, "Executive Summary"),
    React.createElement(
      View,
      { style: S.statsGrid },
      React.createElement(StatCard, { label: "Subdomains", value: stats.subdomains || 0, color: COLORS.accent }),
      React.createElement(StatCard, { label: "IPs Found", value: stats.ips || 0, color: COLORS.green }),
      React.createElement(StatCard, { label: "Findings", value: stats.findings || 0, color: COLORS.red }),
      React.createElement(StatCard, { label: "JS Endpoints", value: stats.js_endpoints || 0, color: COLORS.yellow }),
      React.createElement(StatCard, { label: "Open Ports", value: portCount, color: COLORS.orange }),
      React.createElement(StatCard, { label: "Errors", value: stats.errors || 0, color: COLORS.muted })
    ),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = SummaryPage;
