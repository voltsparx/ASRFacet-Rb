"use strict";

function FindingsPage({ data, helpers }) {
  const { React, Page, Text, View, AccentBar, MetaRow, Footer, S, sevColor, COLORS } = helpers;
  const findings = data.findings || [];

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, `Security Findings (${findings.length})`),
    findings.length === 0
      ? React.createElement(Text, { style: S.emptyState }, "No findings recorded.")
      : findings.map((finding, index) =>
          React.createElement(
            View,
            { key: index, style: { marginBottom: 14 } },
            React.createElement(
              Text,
              { style: S.h3 },
              `${index + 1}. ${finding.title || "Untitled Finding"}`
            ),
            React.createElement(
              View,
              { style: S.metaRow },
              React.createElement(Text, { style: [S.metaLabel, { color: COLORS.muted }] }, "Severity:"),
              React.createElement(
                Text,
                {
                  style: [
                    S.metaValue,
                    { color: sevColor(finding.severity || "info"), fontWeight: "bold" },
                  ],
                },
                (finding.severity || "info").toUpperCase()
              )
            ),
            React.createElement(MetaRow, { label: "Asset", value: finding.asset || "-" }),
            finding.description
              ? React.createElement(Text, {
                  style: { fontSize: 9, color: COLORS.muted, marginTop: 4 },
                }, finding.description)
              : null
          )
        ),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = FindingsPage;
