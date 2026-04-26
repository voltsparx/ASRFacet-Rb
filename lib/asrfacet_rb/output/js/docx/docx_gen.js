"use strict";

const fs = require("fs");
const {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} = require("docx");
const { loadPayload, requireOutputPath } = require("../shared/data_loader");
const { buildAllCharts } = require("../shared/chart_builder");
const { COLORS, severityColor } = require("../shared/colors");

const hex = (value) => value.replace("#", "");

function heading(text, level) {
  return new Paragraph({
    text,
    heading: level,
    spacing: { before: 180, after: 120 },
  });
}

function body(text, opts = {}) {
  return new Paragraph({
    children: [
      new TextRun({
        text: String(text),
        bold: Boolean(opts.bold),
        color: hex(opts.color || COLORS.text),
        size: opts.size || 22,
      }),
    ],
    spacing: { after: opts.after || 100 },
    alignment: opts.align || AlignmentType.LEFT,
  });
}

function divider() {
  return new Paragraph({
    text: "",
    border: {
      bottom: {
        style: BorderStyle.SINGLE,
        size: 6,
        color: hex(COLORS.border),
      },
    },
    spacing: { before: 120, after: 120 },
  });
}

function makeTable(headers, rows) {
  const headerRow = new TableRow({
    tableHeader: true,
    children: headers.map((header) =>
      new TableCell({
        width: { size: 2400, type: WidthType.DXA },
        shading: { fill: hex(COLORS.panelSoft) },
        children: [
          body(header, {
            bold: true,
            color: COLORS.white,
            size: 20,
          }),
        ],
      })
    ),
  });

  return new Table({
    width: { size: 9000, type: WidthType.DXA },
    rows: [
      headerRow,
      ...rows.map((row) =>
        new TableRow({
          children: row.map((cell) =>
            new TableCell({
              children: [body(cell, { size: 18, after: 40 })],
            })
          ),
        })
      ),
    ],
  });
}

function chartParagraph(title, buffer) {
  const parts = [heading(title, HeadingLevel.HEADING_2)];
  if (!buffer) {
    parts.push(body("No chart data available.", { color: COLORS.muted }));
    return parts;
  }

  parts.push(
    new Paragraph({
      children: [
        new ImageRun({
          data: buffer,
          transformation: { width: 560, height: 260 },
          type: "png",
        }),
      ],
    })
  );
  return parts;
}

function buildFindingsTable(findings) {
  const rows = findings.length === 0
    ? [["(none)", "", "", ""]]
    : findings.map((finding) => [
        finding.title || "Untitled",
        finding.severity || "informational",
        finding.asset || finding.host || "",
        finding.description || "",
      ]);

  return makeTable(["Title", "Severity", "Asset", "Description"], rows);
}

async function main() {
  const payload = loadPayload(process.argv[2]);
  const outputPath = requireOutputPath(process.argv[3]);
  const charts = await buildAllCharts(payload.charts || {});

  const statsRows = Object.entries(payload.stats || {}).map(([key, value]) => [
    key.replace(/_/g, " "),
    String(value),
  ]);

  const chartTables = {
    severity: (payload.charts && payload.charts.severity_distribution) || [],
    ports: (payload.charts && payload.charts.port_frequency) || [],
    services: (payload.charts && payload.charts.service_breakdown) || [],
    ipClasses: (payload.charts && payload.charts.ip_class_distribution) || [],
    sources: (payload.charts && payload.charts.subdomain_source_share) || [],
    timeline: (payload.charts && payload.charts.finding_timeline) || [],
  };

  const doc = new Document({
    title: `${payload.meta.title} - ${payload.meta.target}`,
    styles: {
      default: {
        document: {
          run: {
            font: "Segoe UI",
            size: 22,
            color: hex(COLORS.text),
          },
        },
      },
    },
    sections: [
      {
        children: [
          heading(payload.meta.title, HeadingLevel.TITLE),
          body(`Target: ${payload.meta.target}`, { size: 24, color: COLORS.white }),
          body(`Generated: ${payload.meta.generated_at}`, { color: COLORS.muted }),
          body(`Engine: ${payload.meta.engine}`, { color: COLORS.muted }),
          divider(),
          heading("Summary", HeadingLevel.HEADING_1),
          makeTable(["Metric", "Value"], statsRows),
          divider(),
          ...chartParagraph("Severity Distribution", charts.severity),
          ...chartParagraph("Port Frequency", charts.ports),
          ...chartParagraph("Service Breakdown", charts.services),
          ...chartParagraph("IP Class Distribution", charts.ipClasses),
          ...chartParagraph("Subdomain Source Share", charts.sources),
          ...chartParagraph("Finding Timeline", charts.timeline),
          heading("Chart Data Tables", HeadingLevel.HEADING_1),
          makeTable(["Severity", "Count"], chartTables.severity.map((row) => [row.label, String(row.value)])),
          makeTable(["Port", "Count"], chartTables.ports.map((row) => [String(row.port), String(row.value)])),
          makeTable(["Service", "Count"], chartTables.services.map((row) => [row.label, String(row.value)])),
          makeTable(["IP Class", "Count"], chartTables.ipClasses.map((row) => [row.label, String(row.value)])),
          makeTable(["Source", "Count"], chartTables.sources.map((row) => [row.label, String(row.value)])),
          makeTable(["Date", "Count"], chartTables.timeline.map((row) => [row.label, String(row.value)])),
          heading("Subdomains", HeadingLevel.HEADING_1),
          makeTable(["Host", "Sources"], (payload.subdomains || []).map((row) => [row.host, (row.sources || []).join(", ")])),
          heading("IPs", HeadingLevel.HEADING_1),
          makeTable(["IP", "Class", "Ports"], (payload.ips || []).map((row) => [row.ip, row.class, String(row.ports)])),
          heading("Ports", HeadingLevel.HEADING_1),
          makeTable(["Host", "Port", "Service", "Banner"], (payload.ports || []).map((row) => [row.host, String(row.port), row.service, row.banner])),
          heading("Findings", HeadingLevel.HEADING_1),
          buildFindingsTable(payload.findings || []),
          ...(payload.findings || []).flatMap((finding) => [
            new Paragraph({
              children: [
                new TextRun({
                  text: `${finding.title || "Untitled"} - `,
                  bold: true,
                  color: hex(COLORS.white),
                }),
                new TextRun({
                  text: finding.severity || "informational",
                  color: hex(severityColor(finding.severity)),
                  bold: true,
                }),
              ],
            }),
            body(`Asset: ${finding.asset || finding.host || ""}`, { color: COLORS.muted, size: 18 }),
            body(`Description: ${finding.description || "n/a"}`, { size: 18 }),
          ]),
          heading("JavaScript Endpoints", HeadingLevel.HEADING_1),
          makeTable(["Endpoint", "Method", "Source"], (payload.js_endpoints || []).map((row) => [row.endpoint, row.method, row.source])),
          heading("Errors", HeadingLevel.HEADING_1),
          makeTable(["Source", "Message", "Time"], (payload.errors || []).map((row) => [row.source, row.message, row.time])),
        ],
      },
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
}

main().catch((error) => {
  console.error(`[error] docx_gen.js failed: ${error.message}`);
  process.exit(1);
});
