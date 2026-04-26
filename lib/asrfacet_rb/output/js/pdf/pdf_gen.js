"use strict";

require("@babel/register")({
  presets: ["@babel/preset-react"],
  extensions: [".jsx", ".js"],
});

const React = require("react");
const {
  renderToFile,
  Document,
  Page,
  Text,
  View,
  Image,
  StyleSheet,
} = require("@react-pdf/renderer");
const { loadPayload, requireOutputPath } = require("../shared/data_loader");
const { buildAllCharts } = require("../shared/chart_builder");
const { COLORS, sevColor } = require("../shared/colors");
const CoverPage = require("./sections/cover");
const SummaryPage = require("./sections/summary");
const SubdomainsPage = require("./sections/subdomains");
const IpsPortsPage = require("./sections/ips_ports");
const FindingsPage = require("./sections/findings");
const JsEndpointsPage = require("./sections/js_endpoints");
const ChartsPage = require("./sections/charts");

const S = StyleSheet.create({
  page: {
    backgroundColor: COLORS.bg,
    padding: 40,
    fontFamily: "Helvetica",
  },
  accentBar: {
    height: 4,
    backgroundColor: COLORS.accent,
    marginBottom: 20,
    borderRadius: 2,
  },
  h1: {
    fontSize: 26,
    fontWeight: "bold",
    color: COLORS.white,
    marginBottom: 8,
  },
  h2: {
    fontSize: 16,
    fontWeight: "bold",
    color: COLORS.white,
    marginTop: 20,
    marginBottom: 10,
    paddingBottom: 4,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  h3: {
    fontSize: 13,
    fontWeight: "bold",
    color: COLORS.accent,
    marginTop: 12,
    marginBottom: 6,
  },
  metaRow: {
    flexDirection: "row",
    marginBottom: 4,
  },
  metaLabel: {
    fontSize: 10,
    color: COLORS.muted,
    width: 90,
    fontWeight: "bold",
  },
  metaValue: {
    fontSize: 10,
    color: COLORS.text,
    flex: 1,
  },
  statsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
    marginBottom: 20,
  },
  statCard: {
    backgroundColor: COLORS.surface,
    borderRadius: 6,
    padding: 14,
    width: "30%",
    alignItems: "center",
  },
  statValue: {
    fontSize: 22,
    fontWeight: "bold",
    color: COLORS.accent,
  },
  statLabel: {
    fontSize: 9,
    color: COLORS.muted,
    marginTop: 4,
    textTransform: "uppercase",
  },
  chartRow: {
    flexDirection: "row",
    gap: 16,
    marginBottom: 20,
  },
  chartBox: {
    flex: 1,
    backgroundColor: COLORS.surface,
    borderRadius: 6,
    padding: 12,
    alignItems: "center",
  },
  chartTitle: {
    fontSize: 10,
    color: COLORS.muted,
    marginBottom: 8,
    fontWeight: "bold",
    textTransform: "uppercase",
  },
  chartImage: {
    width: 220,
    height: 110,
  },
  table: {
    width: "100%",
    marginBottom: 16,
  },
  tableHeaderRow: {
    flexDirection: "row",
    backgroundColor: "#1C2128",
    paddingVertical: 6,
    paddingHorizontal: 8,
  },
  tableRow: {
    flexDirection: "row",
    paddingVertical: 5,
    paddingHorizontal: 8,
    borderBottomWidth: 0.5,
    borderBottomColor: COLORS.border,
  },
  tableRowAlt: {
    backgroundColor: "#0F1318",
  },
  thCell: {
    fontSize: 8,
    color: COLORS.muted,
    fontWeight: "bold",
    textTransform: "uppercase",
    flex: 1,
  },
  tdCell: {
    fontSize: 9,
    color: COLORS.text,
    flex: 1,
    fontFamily: "Courier",
  },
  emptyState: {
    fontSize: 10,
    color: COLORS.muted,
    fontStyle: "italic",
    marginVertical: 12,
    textAlign: "center",
  },
  footer: {
    position: "absolute",
    bottom: 24,
    left: 40,
    right: 40,
    flexDirection: "row",
    justifyContent: "space-between",
  },
  footerText: {
    fontSize: 8,
    color: COLORS.muted,
  },
  hr: {
    borderBottomWidth: 0.5,
    borderBottomColor: COLORS.border,
    marginVertical: 14,
  },
});

const AccentBar = () => React.createElement(View, { style: S.accentBar });
const HR = () => React.createElement(View, { style: S.hr });
const MetaRow = ({ label, value }) =>
  React.createElement(
    View,
    { style: S.metaRow },
    React.createElement(Text, { style: S.metaLabel }, `${label}:`),
    React.createElement(Text, { style: S.metaValue }, String(value))
  );
const StatCard = ({ label, value, color }) =>
  React.createElement(
    View,
    { style: S.statCard },
    React.createElement(
      Text,
      { style: [S.statValue, { color: color || COLORS.accent }] },
      String(value)
    ),
    React.createElement(Text, { style: S.statLabel }, label)
  );
const TableComp = ({ headers, rows }) =>
  React.createElement(
    View,
    { style: S.table },
    React.createElement(
      View,
      { style: S.tableHeaderRow },
      headers.map((header, index) =>
        React.createElement(Text, { key: index, style: S.thCell }, header)
      )
    ),
    rows.map((row, rowIndex) =>
      React.createElement(
        View,
        {
          key: rowIndex,
          style: [S.tableRow, rowIndex % 2 === 1 ? S.tableRowAlt : {}],
        },
        row.map((cell, cellIndex) =>
          React.createElement(
            Text,
            {
              key: cellIndex,
              style: [
                S.tdCell,
                { color: row._colors && row._colors[cellIndex] ? row._colors[cellIndex] : COLORS.text },
              ],
            },
            String(cell)
          )
        )
      )
    )
  );
const ChartBox = ({ title, imageBuffer }) =>
  React.createElement(
    View,
    { style: S.chartBox },
    React.createElement(Text, { style: S.chartTitle }, title),
    imageBuffer
      ? React.createElement(Image, {
          style: S.chartImage,
          src: imageBuffer,
        })
      : React.createElement(Text, { style: S.emptyState }, "No data")
  );
const Footer = ({ version }) =>
  React.createElement(
    View,
    { style: S.footer },
    React.createElement(Text, { style: S.footerText }, `ASRFacet-Rb v${version}`),
    React.createElement(Text, { style: S.footerText }, "For authorized security research only.")
  );

async function main() {
  const payloadPath = process.argv[2];
  const outputPath = requireOutputPath(process.argv[3]);
  const data = loadPayload(payloadPath);

  console.log("[*] Building charts...");
  const charts = await buildAllCharts(data.charts || {});

  const helpers = {
    React,
    Page,
    Text,
    View,
    Image,
    S,
    COLORS,
    sevColor,
    AccentBar,
    HR,
    MetaRow,
    StatCard,
    TableComp,
    ChartBox,
    Footer,
  };

  console.log("[*] Rendering PDF...");
  const doc = React.createElement(
    Document,
    {
      title: `ASRFacet-Rb - ${data.meta.target}`,
      author: "ASRFacet-Rb",
      subject: "Reconnaissance Report",
      creator: `ASRFacet-Rb v${data.meta.version}`,
    },
    React.createElement(CoverPage, { data, helpers }),
    React.createElement(SummaryPage, { data, helpers }),
    React.createElement(ChartsPage, { charts, data, helpers }),
    React.createElement(SubdomainsPage, { data, helpers }),
    React.createElement(IpsPortsPage, { data, helpers }),
    React.createElement(FindingsPage, { data, helpers }),
    React.createElement(JsEndpointsPage, { data, helpers })
  );

  await renderToFile(doc, outputPath);
  console.log(`[ok] PDF written (react-pdf) -> ${outputPath}`);
}

main().catch((error) => {
  console.error(`[error] pdf_gen.js failed: ${error.message}`);
  process.exit(1);
});
