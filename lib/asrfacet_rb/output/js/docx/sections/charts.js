"use strict";

function buildCharts(charts, helpers) {
  return [
    helpers.heading2("Visualizations"),
    helpers.heading3("Findings by Severity"),
    helpers.imageBlock(charts.severity, "Severity Distribution"),
    helpers.heading3("Top Ports by Frequency"),
    helpers.imageBlock(charts.ports, "Port Frequency"),
    helpers.heading3("Service Breakdown"),
    helpers.imageBlock(charts.services, "Service Types"),
    helpers.heading3("IP Class Distribution"),
    helpers.imageBlock(charts.ipClass, "IP Classes"),
    helpers.hr(),
  ];
}

module.exports = buildCharts;
