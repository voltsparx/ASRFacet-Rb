"use strict";

function SubdomainsPage({ data, helpers }) {
  const { React, Page, Text, AccentBar, TableComp, Footer, S } = helpers;
  const subdomains = data.subdomains || [];
  const rows = subdomains.map((subdomain, index) => [String(index + 1), subdomain]);

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, `Discovered Subdomains (${subdomains.length})`),
    rows.length
      ? React.createElement(TableComp, { headers: ["#", "Subdomain"], rows })
      : React.createElement(Text, { style: S.emptyState }, "No subdomains discovered."),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = SubdomainsPage;
