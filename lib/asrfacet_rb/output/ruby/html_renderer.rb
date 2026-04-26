# frozen_string_literal: true
# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

require "cgi"
require "erb"
require "json"
require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class HtmlRenderer < BaseRenderer
        def render(output_path)
          write!(output_path, build_html)
          log_success("HTML", output_path)
        rescue ASRFacet::Error
          raise
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "HTML render failed: #{e.message}"
        end

        private

        def build_html
          payload = report_payload
          primary_charts = [
            { id: "severity-chart", title: "Severity Distribution", type: "doughnut", data: payload[:charts][:severity_distribution], label_key: :label, value_key: :value },
            { id: "ports-chart", title: "Port Frequency", type: "bar", data: payload[:charts][:port_frequency], label_key: :label, value_key: :value },
            { id: "service-chart", title: "Service Breakdown", type: "pie", data: payload[:charts][:service_breakdown], label_key: :label, value_key: :value },
            { id: "ip-chart", title: "IP Class Distribution", type: "doughnut", data: payload[:charts][:ip_class_distribution], label_key: :label, value_key: :value }
          ]
          secondary_charts = [
            { id: "sources-chart", title: "Subdomain Source Share", type: "bar", data: payload[:charts][:subdomain_source_share], label_key: :label, value_key: :value, horizontal: true },
            { id: "timeline-chart", title: "Finding Timeline", type: "line", data: payload[:charts][:finding_timeline], label_key: :label, value_key: :value }
          ]
          ERB.new(template, trim_mode: "-").result(binding)
        end

        def template
          <<~HTML
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title><%= h(report_title) %> - <%= h(target) %></title>
              <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
              <style>
                :root {
                  --bg: #0b1020;
                  --panel: #151d33;
                  --panel-soft: #1b2540;
                  --panel-strong: #202c4a;
                  --border: #304164;
                  --text: #e7edf7;
                  --muted: #8ea0c0;
                  --accent: #53c2f0;
                  --good: #4fd18b;
                  --warn: #f5b53d;
                  --bad: #ff6767;
                  --violet: #9f84ff;
                  --shadow: 0 18px 40px rgba(3, 6, 15, 0.45);
                }
                * { box-sizing: border-box; }
                body {
                  margin: 0;
                  font-family: "Segoe UI", Tahoma, sans-serif;
                  background:
                    radial-gradient(circle at top left, rgba(83, 194, 240, 0.18), transparent 22rem),
                    radial-gradient(circle at top right, rgba(159, 132, 255, 0.12), transparent 18rem),
                    var(--bg);
                  color: var(--text);
                }
                .page {
                  max-width: 1400px;
                  margin: 0 auto;
                  padding: 32px;
                }
                .hero, .panel {
                  background: linear-gradient(180deg, rgba(32, 44, 74, 0.98), rgba(21, 29, 51, 0.98));
                  border: 1px solid var(--border);
                  border-radius: 20px;
                  box-shadow: var(--shadow);
                }
                .hero {
                  padding: 28px;
                  margin-bottom: 24px;
                }
                .hero h1 {
                  margin: 0 0 10px;
                  font-size: 2.4rem;
                  line-height: 1.1;
                }
                .hero p {
                  margin: 0;
                  color: var(--muted);
                }
                .meta {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                  gap: 12px;
                  margin-top: 22px;
                }
                .meta-card, .stat-card {
                  background: rgba(11, 16, 32, 0.56);
                  border: 1px solid rgba(83, 194, 240, 0.12);
                  border-radius: 16px;
                  padding: 16px;
                }
                .meta-card span, .stat-label {
                  display: block;
                  color: var(--muted);
                  font-size: 0.8rem;
                  text-transform: uppercase;
                  letter-spacing: 0.08em;
                }
                .meta-card strong {
                  display: block;
                  margin-top: 8px;
                  font-size: 1rem;
                }
                .stats-grid {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                  gap: 16px;
                  margin-bottom: 24px;
                }
                .stat-card strong {
                  display: block;
                  margin-top: 10px;
                  font-size: 2rem;
                }
                .panel {
                  padding: 24px;
                  margin-bottom: 24px;
                }
                .panel h2 {
                  margin: 0 0 16px;
                  font-size: 1.3rem;
                }
                .chart-grid {
                  display: grid;
                  grid-template-columns: repeat(2, minmax(0, 1fr));
                  gap: 18px;
                }
                .chart-card {
                  background: rgba(11, 16, 32, 0.55);
                  border: 1px solid rgba(83, 194, 240, 0.12);
                  border-radius: 18px;
                  padding: 18px;
                  min-height: 320px;
                }
                .chart-card.large {
                  min-height: 360px;
                }
                .chart-card h3 {
                  margin: 0 0 14px;
                  font-size: 1rem;
                  color: var(--muted);
                  text-transform: uppercase;
                  letter-spacing: 0.08em;
                }
                .tables {
                  display: grid;
                  gap: 20px;
                }
                table {
                  width: 100%;
                  border-collapse: collapse;
                  overflow: hidden;
                  border-radius: 14px;
                  background: rgba(11, 16, 32, 0.52);
                  border: 1px solid rgba(83, 194, 240, 0.08);
                }
                thead {
                  background: rgba(83, 194, 240, 0.08);
                }
                th, td {
                  padding: 12px 14px;
                  text-align: left;
                  border-bottom: 1px solid rgba(83, 194, 240, 0.08);
                  vertical-align: top;
                }
                th {
                  color: var(--muted);
                  font-size: 0.8rem;
                  text-transform: uppercase;
                  letter-spacing: 0.08em;
                }
                tbody tr:hover {
                  background: rgba(83, 194, 240, 0.05);
                }
                .badge {
                  display: inline-block;
                  padding: 0.28rem 0.65rem;
                  border-radius: 999px;
                  font-size: 0.76rem;
                  font-weight: 700;
                  text-transform: uppercase;
                  letter-spacing: 0.08em;
                }
                .badge-critical { background: rgba(255, 103, 103, 0.18); color: #ff8c8c; }
                .badge-high { background: rgba(255, 103, 103, 0.16); color: #ff8c8c; }
                .badge-medium { background: rgba(245, 181, 61, 0.16); color: #ffd37d; }
                .badge-low { background: rgba(79, 209, 139, 0.16); color: #72e7a7; }
                .badge-informational, .badge-info { background: rgba(83, 194, 240, 0.16); color: #8fdfff; }
                .empty {
                  color: var(--muted);
                  font-style: italic;
                }
                footer {
                  color: var(--muted);
                  text-align: center;
                  padding: 8px 0 32px;
                }
                @media (max-width: 960px) {
                  .page { padding: 18px; }
                  .chart-grid { grid-template-columns: 1fr; }
                }
              </style>
            </head>
            <body>
              <main class="page">
                <section class="hero">
                  <h1><%= h(report_title) %></h1>
                  <p>Dynamic reconnaissance reporting for stored ASRFacet-Rb data.</p>
                  <div class="meta">
                    <div class="meta-card"><span>Target</span><strong><%= h(payload[:meta][:target]) %></strong></div>
                    <div class="meta-card"><span>Generated</span><strong><%= h(payload[:meta][:generated_at]) %></strong></div>
                    <div class="meta-card"><span>Engine</span><strong><%= h(payload[:meta][:engine]) %></strong></div>
                    <div class="meta-card"><span>Version</span><strong><%= h(payload[:meta][:version]) %></strong></div>
                  </div>
                </section>

                <section class="panel">
                  <h2>Summary</h2>
                  <div class="stats-grid">
                    <% payload[:stats].each do |key, value| %>
                      <div class="stat-card">
                        <span class="stat-label"><%= h(key.to_s.tr("_", " ")) %></span>
                        <strong><%= h(value) %></strong>
                      </div>
                    <% end %>
                  </div>
                </section>

                <section class="panel">
                  <h2>Primary Charts</h2>
                  <div class="chart-grid">
                    <% primary_charts.each do |chart| %>
                      <article class="chart-card">
                        <h3><%= h(chart[:title]) %></h3>
                        <canvas id="<%= h(chart[:id]) %>"></canvas>
                      </article>
                    <% end %>
                  </div>
                </section>

                <section class="panel">
                  <h2>Secondary Charts</h2>
                  <div class="chart-grid">
                    <% secondary_charts.each do |chart| %>
                      <article class="chart-card large">
                        <h3><%= h(chart[:title]) %></h3>
                        <canvas id="<%= h(chart[:id]) %>"></canvas>
                      </article>
                    <% end %>
                  </div>
                </section>

                <section class="panel">
                  <h2>Data Tables</h2>
                  <div class="tables">
                    <div>
                      <h3>Subdomains</h3>
                      <%= render_table(["Host", "Sources"], payload[:subdomains].map { |row| [row[:host], row[:sources].join(", ")] }) %>
                    </div>
                    <div>
                      <h3>IPs</h3>
                      <%= render_table(["IP", "Class", "Ports"], payload[:ips].map { |row| [row[:ip], row[:class], row[:ports]] }) %>
                    </div>
                    <div>
                      <h3>Ports</h3>
                      <%= render_table(["Host", "Port", "Service", "Banner"], payload[:ports].map { |row| [row[:host], row[:port], row[:service], row[:banner]] }) %>
                    </div>
                    <div>
                      <h3>Findings</h3>
                      <%= render_findings_table(payload[:findings]) %>
                    </div>
                    <div>
                      <h3>JavaScript Endpoints</h3>
                      <%= render_table(["Endpoint", "Method", "Source"], payload[:js_endpoints].map { |row| [row[:endpoint], row[:method], row[:source]] }) %>
                    </div>
                    <div>
                      <h3>Errors</h3>
                      <%= render_table(["Source", "Message", "Time"], payload[:errors].map { |row| [row[:source], row[:message], row[:time]] }) %>
                    </div>
                  </div>
                </section>
              </main>

              <footer>
                Generated by ASRFacet-Rb v<%= h(version) %>. Authorized lab use only.
              </footer>

              <script>
                const palette = ["#53c2f0", "#4fd18b", "#f5b53d", "#ff6767", "#9f84ff", "#7dd3fc"];
                const chartConfig = {
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      labels: { color: "#e7edf7" }
                    }
                  },
                  scales: {
                    x: {
                      ticks: { color: "#8ea0c0" },
                      grid: { color: "rgba(83, 194, 240, 0.08)" }
                    },
                    y: {
                      beginAtZero: true,
                      ticks: { color: "#8ea0c0" },
                      grid: { color: "rgba(83, 194, 240, 0.08)" }
                    }
                  }
                };
                const charts = <%= JSON.pretty_generate(payload[:charts]) %>;

                const drawChart = (entry) => {
                  const canvas = document.getElementById(entry.id);
                  if (!canvas || !entry.data || entry.data.length === 0) return;
                  const labels = entry.data.map((item) => item[entry.labelKey]);
                  const values = entry.data.map((item) => item[entry.valueKey]);
                  const config = {
                    type: entry.type,
                    data: {
                      labels,
                      datasets: [{
                        data: values,
                        label: entry.title,
                        backgroundColor: palette,
                        borderColor: "#0b1020",
                        borderWidth: 2,
                        fill: entry.type === "line" ? false : true,
                        tension: entry.type === "line" ? 0.3 : 0
                      }]
                    },
                    options: JSON.parse(JSON.stringify(chartConfig))
                  };
                  if (entry.horizontal) {
                    config.options.indexAxis = "y";
                  }
                  if (entry.type === "doughnut" || entry.type === "pie") {
                    delete config.options.scales;
                  }
                  new Chart(canvas, config);
                };

                <%= build_chart_invocations(primary_charts, secondary_charts) %>
              </script>
            </body>
            </html>
          HTML
        end

        def render_table(headers, rows)
          return '<p class="empty">(none)</p>' if rows.empty?

          head = headers.map { |header| "<th>#{h(header)}</th>" }.join
          body = rows.map do |row|
            "<tr>#{row.map { |cell| "<td>#{h(cell)}</td>" }.join}</tr>"
          end.join
          "<table><thead><tr>#{head}</tr></thead><tbody>#{body}</tbody></table>"
        end

        def render_findings_table(rows)
          return '<p class="empty">(none)</p>' if rows.empty?

          headers = %w[Title Severity Asset Description]
          head = headers.map { |header| "<th>#{h(header)}</th>" }.join
          body = rows.map do |row|
            severity = row[:severity].to_s.downcase
            badge = %(<span class="badge badge-#{severity}">#{h(row[:severity])}</span>)
            "<tr><td>#{h(row[:title])}</td><td>#{badge}</td><td>#{h(row[:asset] || row[:host])}</td><td>#{h(row[:description])}</td></tr>"
          end.join
          "<table><thead><tr>#{head}</tr></thead><tbody>#{body}</tbody></table>"
        end

        def build_chart_invocations(*groups)
          groups.flatten.map do |chart|
            "drawChart(#{JSON.generate(chart)});"
          end.join("\n")
        end

        def h(value)
          CGI.escape_html(value.to_s)
        end
      end
    end
  end
end
