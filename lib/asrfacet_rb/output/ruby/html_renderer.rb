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

require "erb"
require "json"
require_relative "../base_renderer"
require_relative "../runtime_detector"

module ASRFacet
  module Output
    module Ruby
      class HtmlRenderer < BaseRenderer
        def render(output_path)
          write!(output_path, build_html)
          log_success("HTML", output_path)
        rescue StandardError => e
          raise ASRFacet::Error, "HTML render failed: #{e.message}"
        end

        private

        def build_html
          charts = (@options[:charts] || {}).to_json
          findings = sorted_findings
          ERB.new(template, trim_mode: "-").result(binding)
        end

        def template
          <<~HTML
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title><%= report_title %></title>
              <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
              <style>
                body { font-family: Segoe UI, sans-serif; margin: 0; padding: 32px; background: #0d1117; color: #c9d1d9; }
                .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
                h1,h2 { margin-top: 0; color: #ffffff; }
                table { width: 100%; border-collapse: collapse; }
                th,td { border-bottom: 1px solid #30363d; padding: 8px; text-align: left; }
                th { color: #8b949e; font-size: 12px; text-transform: uppercase; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
                .chart { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
              </style>
            </head>
            <body>
              <div class="section">
                <h1><%= report_title %></h1>
                <div>Generated: <%= timestamp %></div>
                <div>Engine: <%= RuntimeDetector.engine_label %></div>
                <div>Version: <%= version %></div>
              </div>
              <div class="section">
                <h2>Executive Summary</h2>
                <ul>
                  <% @store.stats.each do |key, value| %>
                    <li><strong><%= key %></strong>: <%= value %></li>
                  <% end %>
                </ul>
              </div>
              <div class="grid">
                <div class="chart"><canvas id="severityChart"></canvas></div>
                <div class="chart"><canvas id="portChart"></canvas></div>
              </div>
              <div class="section">
                <h2>Subdomains</h2>
                <table><thead><tr><th>#</th><th>Subdomain</th></tr></thead><tbody>
                <% @store.subdomains.each_with_index do |subdomain, index| %>
                  <tr><td><%= index + 1 %></td><td><%= subdomain %></td></tr>
                <% end %>
                </tbody></table>
              </div>
              <div class="section">
                <h2>IPs and Ports</h2>
                <table><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead><tbody>
                <% @store.ports.each do |ip, ports| %>
                  <% Array(ports).each do |port| %>
                    <tr><td><%= ip %></td><td><%= port[:port] %></td><td><%= port[:service] %></td><td><%= port[:banner] %></td></tr>
                  <% end %>
                <% end %>
                </tbody></table>
              </div>
              <div class="section">
                <h2>Findings</h2>
                <table><thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Asset</th><th>Description</th></tr></thead><tbody>
                <% findings.each_with_index do |finding, index| %>
                  <tr><td><%= index + 1 %></td><td><%= finding[:title] %></td><td><%= finding[:severity] %></td><td><%= finding[:asset] || finding[:host] %></td><td><%= finding[:description] %></td></tr>
                <% end %>
                </tbody></table>
              </div>
              <div class="section">
                <h2>JS Endpoints</h2>
                <ul>
                <% @store.js_endpoints.each do |endpoint| %>
                  <li><%= endpoint %></li>
                <% end %>
                </ul>
              </div>
              <script>
                const charts = <%= charts %>;
                const severity = charts.severity_distribution || [];
                const ports = charts.port_frequency || [];
                const makeChart = (id, type, labels, data) => new Chart(document.getElementById(id), {
                  type,
                  data: { labels, datasets: [{ data, backgroundColor: ["#58a6ff","#3fb950","#f85149","#d29922","#e3742b"] }] },
                  options: { responsive: true, plugins: { legend: { labels: { color: "#c9d1d9" } } } }
                });
                if (severity.length) makeChart("severityChart", "doughnut", severity.map((s) => s.label), severity.map((s) => s.value));
                if (ports.length) makeChart("portChart", "bar", ports.map((p) => ":" + p.port), ports.map((p) => p.count));
              </script>
            </body>
            </html>
          HTML
        end
      end
    end
  end
end
