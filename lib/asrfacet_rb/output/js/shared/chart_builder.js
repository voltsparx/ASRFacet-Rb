"use strict";

const { ChartJSNodeCanvas } = require("chartjs-node-canvas");
const { COLORS, PALETTE, severityColor } = require("./colors");

const WIDTH = 900;
const HEIGHT = 420;

function mapChart(chartData, title, type, opts = {}) {
  const entries = Array(chartData || []);
  if (entries.length === 0) {
    return null;
  }

  return {
    title,
    type,
    labels: entries.map((entry) => String(entry[opts.labelKey || "label"] ?? entry.label ?? entry.port ?? entry.time ?? "")),
    values: entries.map((entry) => Number(entry[opts.valueKey || "value"] ?? entry.value ?? entry.count ?? 0)),
    horizontal: Boolean(opts.horizontal),
    line: type === "line",
    doughnut: type === "doughnut",
    colors:
      typeof opts.colors === "function"
        ? entries.map(opts.colors)
        : opts.colors || PALETTE,
  };
}

function chartConfig(chart) {
  const options = {
    responsive: false,
    plugins: {
      legend: {
        labels: { color: COLORS.text },
      },
      title: {
        display: true,
        text: chart.title,
        color: COLORS.text,
      },
    },
  };

  if (chart.horizontal) {
    options.indexAxis = "y";
  }

  if (!chart.doughnut) {
    options.scales = {
      x: {
        ticks: { color: COLORS.muted },
        grid: { color: COLORS.border },
      },
      y: {
        beginAtZero: true,
        ticks: { color: COLORS.muted },
        grid: { color: COLORS.border },
      },
    };
  }

  return {
    type: chart.type,
    data: {
      labels: chart.labels,
      datasets: [
        {
          data: chart.values,
          backgroundColor: chart.colors,
          borderColor: COLORS.panel,
          borderWidth: 2,
          fill: chart.line ? false : true,
          tension: chart.line ? 0.25 : 0,
        },
      ],
    },
    options,
  };
}

async function renderChart(chart) {
  if (!chart) {
    return null;
  }

  const canvas = new ChartJSNodeCanvas({
    width: WIDTH,
    height: HEIGHT,
    backgroundColour: COLORS.panel,
  });

  return canvas.renderToBuffer(chartConfig(chart));
}

async function buildAllCharts(chartData) {
  const mapped = {
    severity: mapChart(chartData.severity_distribution, "Severity Distribution", "doughnut", {
      colors: (entry) => severityColor(entry.label),
    }),
    ports: mapChart(chartData.port_frequency, "Port Frequency", "bar"),
    services: mapChart(chartData.service_breakdown, "Service Breakdown", "pie"),
    ipClasses: mapChart(chartData.ip_class_distribution, "IP Class Distribution", "doughnut"),
    sources: mapChart(chartData.subdomain_source_share, "Subdomain Source Share", "bar", { horizontal: true }),
    timeline: mapChart(chartData.finding_timeline, "Finding Timeline", "line"),
  };

  const entries = await Promise.all(
    Object.entries(mapped).map(async ([key, chart]) => [key, await renderChart(chart)])
  );

  return Object.fromEntries(entries);
}

module.exports = {
  buildAllCharts,
};
