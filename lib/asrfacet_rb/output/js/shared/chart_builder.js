"use strict";

const { ChartJSNodeCanvas } = require("chartjs-node-canvas");
const { PALETTE, COLORS, sevColor } = require("./colors");

const WIDTH = 600;
const HEIGHT = 300;

async function renderChart(type, labels, data, opts = {}) {
  const canvas = new ChartJSNodeCanvas({
    width: WIDTH,
    height: HEIGHT,
    backgroundColour: COLORS.surface
  });

  const config = {
    type,
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: opts.colors || PALETTE,
        borderColor: COLORS.bg,
        borderWidth: 2,
        borderRadius: type === "bar" ? 6 : 0,
        ...(opts.dataset || {})
      }]
    },
    options: {
      responsive: false,
      plugins: {
        legend: { labels: { color: COLORS.text, font: { size: 13 } } }
      },
      scales: type === "bar" ? {
        x: { ticks: { color: COLORS.muted }, grid: { color: COLORS.border } },
        y: { ticks: { color: COLORS.muted }, grid: { color: COLORS.border }, beginAtZero: true }
      } : undefined,
      ...(opts.chartOpts || {})
    }
  };

  return canvas.renderToBuffer(config);
}

async function buildSeverityChart(chartData) {
  const severity = chartData.severity_distribution || [];
  if (!severity.length) return null;
  return renderChart("doughnut", severity.map((entry) => entry.label), severity.map((entry) => entry.value), {
    colors: severity.map((entry) => sevColor(entry.label))
  });
}

async function buildPortChart(chartData) {
  const ports = chartData.port_frequency || [];
  if (!ports.length) return null;
  return renderChart("bar", ports.map((entry) => `:${entry.port}`), ports.map((entry) => entry.count), {
    colors: ports.map(() => COLORS.accent)
  });
}

async function buildServiceChart(chartData) {
  const services = chartData.service_breakdown || [];
  if (!services.length) return null;
  return renderChart("pie", services.map((entry) => entry.label), services.map((entry) => entry.value));
}

async function buildIpClassChart(chartData) {
  const ipClasses = chartData.ip_class_distribution || [];
  if (!ipClasses.length) return null;
  return renderChart("doughnut", ipClasses.map((entry) => entry.label), ipClasses.map((entry) => entry.value));
}

async function buildAllCharts(chartData) {
  const [severity, ports, services, ipClass] = await Promise.all([
    buildSeverityChart(chartData),
    buildPortChart(chartData),
    buildServiceChart(chartData),
    buildIpClassChart(chartData)
  ]);
  return { severity, ports, services, ipClass };
}

module.exports = {
  buildAllCharts,
  buildSeverityChart,
  buildPortChart,
  buildServiceChart,
  buildIpClassChart
};
