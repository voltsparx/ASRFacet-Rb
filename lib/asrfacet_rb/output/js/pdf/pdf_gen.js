"use strict";

require("@babel/register")({
  presets: ["@babel/preset-react"],
  extensions: [".js", ".jsx"],
});

const React = require("react");
const {
  Document,
  Image,
  Page,
  StyleSheet,
  Text,
  View,
  renderToFile,
} = require("@react-pdf/renderer");
const { loadPayload, requireOutputPath } = require("../shared/data_loader");
const { buildAllCharts } = require("../shared/chart_builder");
const { COLORS, severityColor } = require("../shared/colors");

const styles = StyleSheet.create({
  page: {
    backgroundColor: COLORS.bg,
    color: COLORS.text,
    padding: 32,
    fontFamily: "Helvetica",
    fontSize: 10,
  },
  hero: {
    marginBottom: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 700,
    color: COLORS.white,
    marginBottom: 8,
  },
  subtitle: {
    color: COLORS.muted,
    marginBottom: 4,
  },
  statsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
    marginTop: 18,
  },
  statCard: {
    width: "31%",
    backgroundColor: COLORS.panel,
    borderRadius: 10,
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  statValue: {
    color: COLORS.accent,
    fontSize: 18,
    fontWeight: 700,
    marginTop: 6,
  },
  sectionTitle: {
    color: COLORS.white,
    fontSize: 16,
    fontWeight: 700,
    marginBottom: 10,
  },
  chartGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 12,
  },
  chartCard: {
    width: "48%",
    backgroundColor: COLORS.panel,
    padding: 12,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 12,
  },
  chartTitle: {
    color: COLORS.muted,
    fontSize: 9,
    marginBottom: 8,
    textTransform: "uppercase",
  },
  chartImage: {
    width: 240,
    height: 120,
  },
  table: {
    display: "table",
    width: "100%",
    borderWidth: 1,
    borderColor: COLORS.border,
    borderStyle: "solid",
    marginBottom: 12,
  },
  row: {
    flexDirection: "row",
  },
  rowAlt: {
    backgroundColor: COLORS.panelSoft,
  },
  headCell: {
    flex: 1,
    padding: 8,
    backgroundColor: COLORS.panel,
    color: COLORS.muted,
    fontSize: 8,
    fontWeight: 700,
  },
  cell: {
    flex: 1,
    padding: 8,
    color: COLORS.text,
    fontSize: 9,
  },
  footer: {
    position: "absolute",
    bottom: 18,
    left: 32,
    right: 32,
    flexDirection: "row",
    justifyContent: "space-between",
    color: COLORS.muted,
    fontSize: 8,
  },
});

function Footer({ version, page }) {
  return React.createElement(
    View,
    { style: styles.footer, fixed: true },
    React.createElement(Text, null, `ASRFacet-Rb v${version}`),
    React.createElement(Text, null, `Page ${page}`),
  );
}

function StatCard({ label, value }) {
  return React.createElement(
    View,
    { style: styles.statCard },
    React.createElement(Text, { style: styles.subtitle }, label),
    React.createElement(Text, { style: styles.statValue }, String(value)),
  );
}

function ChartCard({ title, buffer }) {
  return React.createElement(
    View,
    { style: styles.chartCard },
    React.createElement(Text, { style: styles.chartTitle }, title),
    buffer
      ? React.createElement(Image, { style: styles.chartImage, src: buffer })
      : React.createElement(Text, { style: styles.subtitle }, "No data"),
  );
}

function Table({ headers, rows }) {
  return React.createElement(
    View,
    { style: styles.table },
    React.createElement(
      View,
      { style: styles.row },
      headers.map((header, index) =>
        React.createElement(Text, { key: index, style: styles.headCell }, header)
      )
    ),
    rows.map((row, rowIndex) =>
      React.createElement(
        View,
        { key: rowIndex, style: [styles.row, rowIndex % 2 === 1 ? styles.rowAlt : null] },
        row.map((cell, cellIndex) =>
          React.createElement(Text, { key: cellIndex, style: styles.cell }, String(cell))
        )
      )
    )
  );
}

async function main() {
  const payload = loadPayload(process.argv[2]);
  const outputPath = requireOutputPath(process.argv[3]);
  const charts = await buildAllCharts(payload.charts || {});

  const pages = React.createElement(
    Document,
    { title: `${payload.meta.title} - ${payload.meta.target}` },
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(
        View,
        { style: styles.hero },
        React.createElement(Text, { style: styles.title }, payload.meta.title),
        React.createElement(Text, { style: styles.subtitle }, `Target: ${payload.meta.target}`),
        React.createElement(Text, { style: styles.subtitle }, `Generated: ${payload.meta.generated_at}`),
        React.createElement(Text, { style: styles.subtitle }, `Engine: ${payload.meta.engine}`)
      ),
      React.createElement(
        View,
        { style: styles.statsGrid },
        ...Object.entries(payload.stats || {}).map(([label, value]) =>
          React.createElement(StatCard, { key: label, label: label.replace(/_/g, " "), value })
        )
      ),
      React.createElement(Footer, { version: payload.meta.version, page: 1 })
    ),
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(Text, { style: styles.sectionTitle }, "Charts"),
      React.createElement(
        View,
        { style: styles.chartGrid },
        React.createElement(ChartCard, { title: "Severity Distribution", buffer: charts.severity }),
        React.createElement(ChartCard, { title: "Port Frequency", buffer: charts.ports }),
        React.createElement(ChartCard, { title: "Service Breakdown", buffer: charts.services }),
        React.createElement(ChartCard, { title: "IP Class Distribution", buffer: charts.ipClasses }),
        React.createElement(ChartCard, { title: "Subdomain Source Share", buffer: charts.sources }),
        React.createElement(ChartCard, { title: "Finding Timeline", buffer: charts.timeline })
      ),
      React.createElement(Footer, { version: payload.meta.version, page: 2 })
    ),
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(Text, { style: styles.sectionTitle }, "Subdomains"),
      React.createElement(Table, {
        headers: ["Host", "Sources"],
        rows: (payload.subdomains || []).map((row) => [row.host, (row.sources || []).join(", ")]),
      }),
      React.createElement(Text, { style: styles.sectionTitle }, "IPs and Ports"),
      React.createElement(Table, {
        headers: ["IP", "Class", "Ports"],
        rows: (payload.ips || []).map((row) => [row.ip, row.class, row.ports]),
      }),
      React.createElement(Table, {
        headers: ["Host", "Port", "Service", "Banner"],
        rows: (payload.ports || []).map((row) => [row.host, row.port, row.service, row.banner]),
      }),
      React.createElement(Footer, { version: payload.meta.version, page: 3 })
    ),
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(Text, { style: styles.sectionTitle }, "Findings"),
      React.createElement(Table, {
        headers: ["Title", "Severity", "Asset", "Description"],
        rows: (payload.findings || []).map((row) => [
          row.title || "Untitled",
          row.severity || "informational",
          row.asset || row.host || "",
          row.description || "",
        ]),
      }),
      ...(payload.findings || []).map((row, index) =>
        React.createElement(
          View,
          { key: index, style: { marginBottom: 10 } },
          React.createElement(Text, { style: { color: severityColor(row.severity), fontWeight: 700 } }, `${row.title || "Untitled"} - ${row.severity || "informational"}`),
          React.createElement(Text, { style: styles.subtitle }, `Asset: ${row.asset || row.host || ""}`),
          React.createElement(Text, { style: styles.cell }, row.description || "n/a")
        )
      ),
      React.createElement(Footer, { version: payload.meta.version, page: 4 })
    ),
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(Text, { style: styles.sectionTitle }, "JavaScript Endpoints"),
      React.createElement(Table, {
        headers: ["Endpoint", "Method", "Source"],
        rows: (payload.js_endpoints || []).map((row) => [row.endpoint, row.method, row.source]),
      }),
      React.createElement(Text, { style: styles.sectionTitle }, "Errors"),
      React.createElement(Table, {
        headers: ["Source", "Message", "Time"],
        rows: (payload.errors || []).map((row) => [row.source, row.message, row.time]),
      }),
      React.createElement(Footer, { version: payload.meta.version, page: 5 })
    )
  );

  await renderToFile(pages, outputPath);
}

main().catch((error) => {
  console.error(`[error] pdf_gen.js failed: ${error.message}`);
  process.exit(1);
});
