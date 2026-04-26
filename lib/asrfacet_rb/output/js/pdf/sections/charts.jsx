"use strict";

function ChartsPage({ charts, data, helpers }) {
  const { React, Page, Text, View, AccentBar, ChartBox, Footer, S } = helpers;

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h2 }, "Visualizations"),
    React.createElement(
      View,
      { style: S.chartRow },
      React.createElement(ChartBox, {
        title: "Findings by Severity",
        imageBuffer: charts.severity,
      }),
      React.createElement(ChartBox, {
        title: "Top Ports by Frequency",
        imageBuffer: charts.ports,
      })
    ),
    React.createElement(
      View,
      { style: S.chartRow },
      React.createElement(ChartBox, {
        title: "Service Breakdown",
        imageBuffer: charts.services,
      }),
      React.createElement(ChartBox, {
        title: "IP Class Distribution",
        imageBuffer: charts.ipClass,
      })
    ),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = ChartsPage;
