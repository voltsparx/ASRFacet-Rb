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

require "json"
require "webrick"

module ASRFacet
  module Web
    class Server
      DEFAULT_HOST = "127.0.0.1"
      DEFAULT_PORT = 4567
      ARTIFACT_KEYS = %w[cli_report txt_report html_report json_report].freeze

      def initialize(host: DEFAULT_HOST, port: DEFAULT_PORT, session_store: nil, session_runner: nil)
        @host = host.to_s.strip.empty? ? DEFAULT_HOST : host.to_s.strip
        @port = port.to_i.positive? ? port.to_i : DEFAULT_PORT
        @session_store = session_store || ASRFacet::Web::SessionStore.new
        @session_runner = session_runner || ASRFacet::Web::SessionRunner.new(session_store: @session_store)
        @server = nil
      rescue StandardError
        @host = DEFAULT_HOST
        @port = DEFAULT_PORT
        @session_store = session_store || ASRFacet::Web::SessionStore.new
        @session_runner = session_runner || ASRFacet::Web::SessionRunner.new(session_store: @session_store)
        @server = nil
      end

      def start
        @server = WEBrick::HTTPServer.new(
          BindAddress: @host,
          Port: @port,
          AccessLog: [],
          Logger: WEBrick::Log.new($stderr, WEBrick::Log::FATAL)
        )
        mount_routes
        trap_signals
        ASRFacet::Core::ThreadSafe.print_status("Web session control panel listening on http://#{@host}:#{@port}")
        ASRFacet::Core::ThreadSafe.print_status("Saved sessions are stored in #{@session_store.root}")
        @server.start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error("Web session startup failed: #{e.message}")
        nil
      ensure
        shutdown
      end

      def shutdown
        @server&.shutdown
      rescue StandardError
        nil
      end

      private

      def mount_routes
        @server.mount_proc("/") { |_req, res| respond_html(res, dashboard_html) }
        @server.mount_proc("/api/bootstrap") { |_req, res| handle_bootstrap(res) }
        @server.mount_proc("/api/sessions") { |req, res| handle_sessions(req, res) }
        @server.mount_proc("/api/session") { |req, res| handle_session_lookup(req, res) }
        @server.mount_proc("/api/run") { |req, res| handle_run(req, res) }
        @server.mount_proc("/reports") { |req, res| handle_reports(req, res) }
        @server.mount_proc("/assets/icon") { |_req, res| handle_icon(res) }
      rescue StandardError
        nil
      end

      def trap_signals
        %w[INT TERM].each do |signal|
          Signal.trap(signal) { shutdown }
        rescue StandardError
          nil
        end
      rescue StandardError
        nil
      end

      def handle_bootstrap(res)
        respond_json(
          res,
          {
            server: {
              host: @host,
              port: @port,
              sessions_root: @session_store.root,
              reports_root: reports_root,
              framework_icon: "/assets/icon"
            },
            defaults: default_config,
            sessions: @session_store.list_sessions.map { |session| summarize_session(session) }
          }
        )
      rescue StandardError
        respond_json(res, { error: "bootstrap_failed" }, status: 500)
      end

      def handle_sessions(req, res)
        if req.request_method == "GET"
          return respond_json(res, { sessions: @session_store.list_sessions.map { |session| summarize_session(session) } })
        end
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless req.request_method == "POST"

        session = @session_store.create_or_update(normalize_session_payload(parse_json(req)))
        session ? respond_json(res, { session: session }) : respond_json(res, { error: "save_failed" }, status: 422)
      rescue StandardError
        respond_json(res, { error: "session_error" }, status: 500)
      end

      def handle_session_lookup(req, res)
        session = @session_store.fetch(req.query["id"].to_s)
        session ? respond_json(res, { session: session }) : respond_json(res, { error: "not_found" }, status: 404)
      rescue StandardError
        respond_json(res, { error: "lookup_failed" }, status: 500)
      end

      def handle_run(req, res)
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless req.request_method == "POST"

        session_id = req.query["id"].to_s
        return respond_json(res, { error: "not_found" }, status: 404) if @session_store.fetch(session_id).nil?

        if @session_runner.start(session_id)
          @session_store.append_event(session_id, type: "system", message: "Run queued from the web control panel.")
          respond_json(res, { ok: true, session_id: session_id })
        else
          respond_json(res, { ok: false, error: "already_running" }, status: 409)
        end
      rescue StandardError
        respond_json(res, { error: "run_failed" }, status: 500)
      end

      def handle_reports(req, res)
        parts = req.path.to_s.split("/").reject(&:empty?)
        return respond_json(res, { error: "not_found" }, status: 404) unless parts.size == 3

        session_id = parts[1]
        key = parts[2]
        return respond_json(res, { error: "forbidden" }, status: 403) unless ARTIFACT_KEYS.include?(key)

        path = @session_store.fetch(session_id).to_h.dig(:artifacts, key.to_sym).to_s
        return respond_json(res, { error: "not_found" }, status: 404) unless File.file?(path)

        res.status = 200
        res["Cache-Control"] = "no-store"
        res["Content-Type"] = content_type_for(path)
        res.body = File.binread(path)
      rescue StandardError
        respond_json(res, { error: "report_failed" }, status: 500)
      end

      def handle_icon(res)
        return respond_json(res, { error: "icon_not_found" }, status: 404) unless File.file?(framework_icon_path)

        res.status = 200
        res["Cache-Control"] = "public, max-age=86400"
        res["Content-Type"] = "image/png"
        res.body = File.binread(framework_icon_path)
      rescue StandardError
        respond_json(res, { error: "icon_failed" }, status: 500)
      end

      def normalize_session_payload(payload)
        item = symbolize(payload)
        item[:name] = item[:name].to_s.strip.empty? ? "Untitled session" : item[:name].to_s.strip
        item[:config] = default_config.merge(symbolize(item[:config] || {}))
        item
      rescue StandardError
        { name: "Untitled session", config: default_config }
      end

      def summarize_session(session)
        item = symbolize(session)
        {
          id: item[:id],
          name: item[:name],
          status: item[:status],
          running: item[:running],
          target: item.dig(:config, :target),
          mode: item.dig(:config, :mode),
          updated_at: item[:updated_at],
          last_heartbeat_at: item[:last_heartbeat_at],
          summary: item[:summary] || {},
          current_stage: item[:current_stage] || {},
          artifacts: item[:artifacts] || {},
          error: item[:error]
        }
      rescue StandardError
        {}
      end

      def default_config
        {
          mode: "scan",
          target: "",
          ports: "top100",
          threads: 50,
          timeout: 10,
          scope: "",
          exclude: "",
          format: "html",
          delay: 0,
          monitor: true,
          memory: true,
          headless: false,
          verbose: true,
          adaptive_rate: true,
          webhook_url: "",
          webhook_platform: "slack",
          shodan_key: ""
        }
      rescue StandardError
        {}
      end

      def reports_root
        File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
      rescue StandardError
        File.expand_path("~/.asrfacet_rb/output")
      end

      def framework_icon_path
        File.expand_path("../../../docs/images/illustration/asrfacet-rb-logo.png", __dir__)
      rescue StandardError
        ""
      end

      def parse_json(req)
        return {} if req.body.to_s.strip.empty?

        JSON.parse(req.body)
      rescue StandardError
        {}
      end

      def respond_json(res, payload, status: 200)
        res.status = status
        res["Content-Type"] = "application/json; charset=utf-8"
        res["Cache-Control"] = "no-store"
        res.body = JSON.pretty_generate(payload)
      rescue StandardError
        nil
      end

      def respond_html(res, html, status: 200)
        res.status = status
        res["Content-Type"] = "text/html; charset=utf-8"
        res["Cache-Control"] = "no-store"
        res.body = html.to_s
      rescue StandardError
        nil
      end

      def content_type_for(path)
        return "text/html; charset=utf-8" if path.end_with?(".html")
        return "application/json; charset=utf-8" if path.end_with?(".json")

        "text/plain; charset=utf-8"
      rescue StandardError
        "application/octet-stream"
      end

      def symbolize(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, nested), memo| memo[key.to_sym] = symbolize(nested) }
        when Array
          value.map { |entry| symbolize(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end

      def dashboard_html
        <<~HTML
          <!DOCTYPE html>
          <html lang="en" data-theme="light">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="color-scheme" content="light dark">
            <link rel="icon" type="image/png" href="/assets/icon">
            <title>ASRFacet-Rb Web Session</title>
            <style>#{styles_css}</style>
          </head>
          <body>
            <div class="layout">
              <aside class="sidebar">
                <section class="brand-card">
                  <img src="/assets/icon" alt="ASRFacet-Rb logo">
                  <div>
                    <h1>ASRFacet-Rb</h1>
                    <p>Operator-focused recon control panel with autosaved sessions, detailed reports, and crash-tolerant recovery.</p>
                  </div>
                </section>
                <section class="status-card">
                  <div class="tiny muted">Local-only dashboard</div>
                  <div class="status-value">http://#{@host}:#{@port}</div>
                  <div class="status-grid">
                    <div class="mini-stat"><span class="tiny muted">Session drafts</span><strong id="meta-sessions">0</strong></div>
                    <div class="mini-stat"><span class="tiny muted">Report root</span><strong id="meta-reports">Ready</strong></div>
                  </div>
                </section>
                <nav class="quick-nav">
                  <h2>Sections</h2>
                  <a href="#overview">Overview</a>
                  <a href="#configuration">Configuration</a>
                  <a href="#activity">Live Activity</a>
                  <a href="#guidance">Guidance</a>
                </nav>
                <section class="sessions-card">
                  <div class="section-head">
                    <h2>Saved Sessions</h2>
                    <div class="controls">
                      <button id="new-session" class="secondary">New</button>
                      <button id="refresh-sessions" class="secondary">Refresh</button>
                    </div>
                  </div>
                  <div id="session-list" class="session-list"></div>
                </section>
                <section class="footer-card tiny muted">
                  Session drafts survive accidental closes, process crashes, and power interruptions. Reports stay under <strong>#{reports_root}</strong>.
                </section>
              </aside>
              <main class="main">
                <section class="topbar">
                  <div class="toolbar-card controls spread">
                    <div class="controls">
                      <span id="status-pill" class="pill">idle</span>
                      <span id="save-note" class="tiny muted">Dirty drafts and active runs trigger a save prompt before the page closes.</span>
                    </div>
                    <div class="controls">
                      <button id="save-session" class="secondary">Save Session</button>
                      <button id="run-session" class="warn">Run Session</button>
                    </div>
                  </div>
                  <div class="toolbar-card controls theme-card">
                    <span class="tiny muted">Theme</span>
                    <div class="theme-switch" role="group" aria-label="Theme switch">
                      <button id="theme-light" data-theme="light" class="active">Light</button>
                      <button id="theme-dark" data-theme="dark">Dark</button>
                      <button id="theme-grey" data-theme="grey">Grey</button>
                    </div>
                  </div>
                </section>
                <section id="overview" class="hero-card">
                  <div class="hero-copy">
                    <h2>Recon session command deck</h2>
                    <p>This local control panel keeps scope planning, run execution, live review, and report access in one place. It follows the same pipeline behavior as the CLI while giving you a richer operating surface and persistent session memory.</p>
                  </div>
                  <div class="hero-meta">
                    <div class="hero-chip"><span class="tiny muted">Theme</span><strong id="theme-name">Light</strong></div>
                    <div class="hero-chip"><span class="tiny muted">Last heartbeat</span><strong id="heartbeat-label">Idle</strong></div>
                    <div class="hero-chip"><span class="tiny muted">Session storage</span><strong>Atomic JSON</strong></div>
                    <div class="hero-chip"><span class="tiny muted">Recovery mode</span><strong>Interrupted runs detected</strong></div>
                  </div>
                </section>
                <section class="dashboard-grid">
                  <section id="configuration" class="card">
                    <h2>Session Configuration</h2>
                    <div class="form-grid">
                      <div class="field"><label for="name">Session Name</label><input id="name" placeholder="Production perimeter review"></div>
                      <div class="field"><label for="target">Target</label><input id="target" placeholder="example.com or 10.0.0.5"></div>
                      <div class="field"><label for="mode">Mode</label><select id="mode"><option value="scan">Full scan</option><option value="passive">Passive</option><option value="dns">DNS only</option><option value="ports">Ports only</option></select></div>
                      <div class="field"><label for="format">Preferred Report</label><select id="format"><option value="html">HTML</option><option value="txt">TXT</option><option value="json">JSON</option><option value="cli">CLI</option></select></div>
                      <div class="field"><label for="ports">Ports</label><input id="ports" placeholder="top100 or 80,443"></div>
                      <div class="field"><label for="threads">Threads</label><input id="threads" type="number" min="1"></div>
                      <div class="field"><label for="timeout">Timeout (seconds)</label><input id="timeout" type="number" min="1"></div>
                      <div class="field"><label for="delay">Base Delay (ms)</label><input id="delay" type="number" min="0"></div>
                      <div class="field"><label for="scope">Allowlist Scope</label><input id="scope" placeholder="example.com,*.example.com"></div>
                      <div class="field"><label for="exclude">Excluded Targets</label><input id="exclude" placeholder="dev.example.com"></div>
                      <div class="field"><label for="webhook-url">Webhook URL</label><input id="webhook-url" placeholder="Optional"></div>
                      <div class="field"><label for="webhook-platform">Webhook Platform</label><select id="webhook-platform"><option value="slack">Slack</option><option value="discord">Discord</option></select></div>
                      <div class="field"><label for="shodan-key">Shodan Key</label><input id="shodan-key" placeholder="Optional"></div>
                    </div>
                    <div class="checks">
                      <label class="check"><input id="monitor" type="checkbox"> Change monitoring</label>
                      <label class="check"><input id="memory" type="checkbox"> Recon memory</label>
                      <label class="check"><input id="headless" type="checkbox"> Headless SPA probing</label>
                      <label class="check"><input id="verbose" type="checkbox"> Live verbose events</label>
                      <label class="check"><input id="adaptive-rate" type="checkbox"> Adaptive rate control</label>
                    </div>
                  </section>
                  <section class="card">
                    <h2>Run Summary</h2>
                    <div class="stats">
                      <div class="stat"><span class="tiny muted">Subdomains</span><strong id="sum-subdomains">0</strong></div>
                      <div class="stat"><span class="tiny muted">IPs</span><strong id="sum-ips">0</strong></div>
                      <div class="stat"><span class="tiny muted">Ports</span><strong id="sum-ports">0</strong></div>
                      <div class="stat"><span class="tiny muted">Web</span><strong id="sum-web">0</strong></div>
                      <div class="stat"><span class="tiny muted">Findings</span><strong id="sum-findings">0</strong></div>
                    </div>
                    <div class="stage">
                      <div>
                        <strong>Current Stage</strong>
                        <div id="stage-name" class="tiny muted stage-label">Waiting for a run.</div>
                      </div>
                      <div id="stage-phase" class="pill">idle</div>
                    </div>
                    <div class="visual-grid">
                      <div id="bar-chart" class="chart"></div>
                      <div class="pie-panel">
                        <div class="pie"></div>
                        <div class="tiny muted">Coverage mix mirrors the current balance between hosts, web exposure, and findings.</div>
                      </div>
                    </div>
                    <div class="report-wrap">
                      <strong>Saved Reports</strong>
                      <div id="report-links" class="report-links"></div>
                    </div>
                  </section>
                </section>
                <section class="lower-grid">
                  <section id="activity" class="card">
                    <h2>Live Activity</h2>
                    <div id="activity-log" class="log"></div>
                  </section>
                  <section id="guidance" class="card">
                    <h2>Guidance</h2>
                    <table>
                      <thead><tr><th>Item</th><th>Meaning</th><th>Recommendation</th></tr></thead>
                      <tbody id="detail-table"></tbody>
                    </table>
                  </section>
                </section>
                <section class="lower-grid">
                  <section class="card">
                    <h2>Top Targets</h2>
                    <table>
                      <thead><tr><th>Asset</th><th>Score</th><th>Why it matters</th></tr></thead>
                      <tbody id="top-assets-table"></tbody>
                    </table>
                  </section>
                  <section class="card">
                    <h2>Recent Findings</h2>
                    <table>
                      <thead><tr><th>Severity</th><th>Title</th><th>Host</th></tr></thead>
                      <tbody id="findings-table"></tbody>
                    </table>
                  </section>
                </section>
              </main>
            </div>
            <script>#{client_script}</script>
          </body>
          </html>
        HTML
      rescue StandardError
        "<!DOCTYPE html><html><body><h1>ASRFacet-Rb</h1></body></html>"
      end

      def styles_css
        <<~CSS
          :root {
            #{ASRFacet::Colors.css_variables}
            --bg: var(--sand_beige);
            --bg-2: #fff8ef;
            --panel: rgba(255,255,255,.86);
            --line: rgba(221,207,187,.82);
            --shadow: 0 18px 44px rgba(31,26,23,.10);
            --text: var(--charcoal_black);
            --muted: var(--stone_brown);
            --accent: var(--crimson_red);
            --accent-2: var(--forest_green);
            --accent-3: var(--cobalt_blue);
            --warn: var(--amber_yellow);
            --danger: var(--cardinal_red);
            --soft: rgba(199,24,0,.08);
            --sidebar: linear-gradient(180deg, rgba(255,247,232,.96) 0%, rgba(255,253,249,.88) 100%);
            --card-grad: linear-gradient(180deg, rgba(255,255,255,.95) 0%, rgba(255,247,232,.82) 100%);
            --log-bg: #13110f;
            --log-text: #e9dbc2;
          }
          html[data-theme="dark"] {
            --bg: #17120f; --bg-2: #241c17; --panel: rgba(31,26,23,.88);
            --line: rgba(93,82,72,.72); --shadow: 0 18px 44px rgba(0,0,0,.34);
            --text: #f5ecdf; --muted: #c7b8a3; --accent: #ff6e4a; --accent-2: #57c56d;
            --accent-3: #73a6ff; --warn: #e3bc55; --danger: #ff6b6b; --soft: rgba(255,110,74,.12);
            --sidebar: linear-gradient(180deg, rgba(35,28,24,.96) 0%, rgba(23,18,15,.96) 100%);
            --card-grad: linear-gradient(180deg, rgba(35,28,24,.96) 0%, rgba(29,23,19,.88) 100%);
            --log-bg: #0b0a09; --log-text: #f5ecdf;
          }
          html[data-theme="grey"] {
            --bg: #dde1e6; --bg-2: #f1f3f5; --panel: rgba(255,255,255,.82);
            --line: rgba(173,181,189,.72); --shadow: 0 16px 38px rgba(73,80,87,.12);
            --text: #212529; --muted: #495057; --accent: #495057; --accent-2: #2b8a3e;
            --accent-3: #3b5bdb; --warn: #c08b1f; --danger: #c92a2a; --soft: rgba(73,80,87,.10);
            --sidebar: linear-gradient(180deg, rgba(248,249,250,.94) 0%, rgba(233,236,239,.94) 100%);
            --card-grad: linear-gradient(180deg, rgba(255,255,255,.96) 0%, rgba(241,243,245,.90) 100%);
            --log-bg: #202428; --log-text: #f8f9fa;
          }
          * { box-sizing: border-box; }
          html, body { margin: 0; min-height: 100%; }
          body {
            font-family: "Segoe UI", "Trebuchet MS", Arial, sans-serif;
            background:
              radial-gradient(circle at top left, rgba(199,24,0,.10), transparent 30%),
              radial-gradient(circle at bottom right, rgba(47,158,68,.10), transparent 28%),
              linear-gradient(135deg, var(--bg) 0%, var(--bg-2) 100%);
            color: var(--text);
          }
          a { color: inherit; }
          .layout { display: grid; grid-template-columns: 300px 1fr; min-height: 100vh; }
          .sidebar { background: var(--sidebar); border-right: 1px solid var(--line); padding: 24px 18px; display: grid; grid-template-rows: auto auto auto 1fr auto; gap: 16px; }
          .brand-card, .status-card, .quick-nav, .sessions-card, .footer-card, .toolbar-card, .hero-card, .card { border: 1px solid var(--line); background: var(--card-grad); border-radius: 22px; box-shadow: var(--shadow); }
          .brand-card { padding: 18px; display: grid; grid-template-columns: 72px 1fr; gap: 14px; align-items: center; }
          .brand-card img { width: 72px; height: 72px; object-fit: contain; border-radius: 18px; background: rgba(255,255,255,.68); padding: 10px; }
          .brand-card h1, .quick-nav h2, .sessions-card h2, .card h2 { margin: 0; }
          .brand-card p, .hero-copy p { margin: 8px 0 0; color: var(--muted); line-height: 1.5; }
          .status-card, .quick-nav, .sessions-card, .footer-card, .toolbar-card, .hero-card, .card { padding: 18px; }
          .status-value { margin-top: 6px; font-weight: 700; }
          .status-grid, .hero-meta, .stats, .checks, .form-grid, .lower-grid, .visual-grid, .dashboard-grid { display: grid; gap: 12px; }
          .status-grid, .hero-meta, .checks, .form-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          .stats { grid-template-columns: repeat(5, minmax(0, 1fr)); }
          .dashboard-grid { grid-template-columns: 1.08fr .92fr; }
          .visual-grid { grid-template-columns: 1.15fr .85fr; margin-top: 14px; }
          .lower-grid { grid-template-columns: 1fr 1fr; }
          .mini-stat, .hero-chip, .stat, .stage, .check, .session, .chart, .pie-panel, table { background: rgba(255,255,255,.80); border: 1px solid var(--line); border-radius: 18px; }
          .mini-stat, .hero-chip, .stat, .stage { padding: 14px; }
          .hero-chip strong, .mini-stat strong, .stat strong { display: block; margin-top: 6px; font-size: 1.35rem; }
          .main { padding: 22px; display: grid; gap: 16px; }
          .topbar { display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center; }
          .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
          .spread { justify-content: space-between; }
          .theme-card { justify-content: flex-end; }
          button, a.button { border: none; border-radius: 14px; padding: 11px 15px; background: var(--accent); color: #fff; text-decoration: none; cursor: pointer; font: inherit; }
          button.secondary, a.button.secondary { background: rgba(255,255,255,.74); color: var(--text); border: 1px solid var(--line); }
          button.warn { background: linear-gradient(135deg, var(--warn) 0%, var(--accent) 100%); }
          .theme-switch { display: inline-flex; gap: 6px; padding: 6px; background: rgba(255,255,255,.68); border: 1px solid var(--line); border-radius: 999px; }
          .theme-switch button { padding: 8px 12px; border-radius: 999px; background: transparent; color: var(--muted); border: 1px solid transparent; }
          .theme-switch button.active { background: var(--accent); color: #fff; }
          .pill { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px; border-radius: 999px; background: var(--soft); color: var(--accent); font-size: .86rem; font-weight: 600; }
          .pill.running { color: var(--warn); }
          .pill.failed, .pill.interrupted { color: var(--danger); }
          .muted { color: var(--muted); }
          .tiny { font-size: .83rem; }
          .section-head { display: flex; justify-content: space-between; gap: 10px; align-items: center; margin-bottom: 12px; }
          .quick-nav a { display: block; padding: 10px 12px; margin-top: 8px; text-decoration: none; border-radius: 14px; background: rgba(255,255,255,.56); }
          .session-list { display: grid; gap: 10px; max-height: calc(100vh - 560px); overflow: auto; padding-right: 4px; }
          .session { padding: 14px; cursor: pointer; }
          .session.active { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(199,24,0,.10); }
          .hero-card { display: grid; grid-template-columns: 1.2fr .8fr; gap: 18px; align-items: stretch; }
          .hero-copy h2 { font-size: 1.45rem; }
          .field { display: flex; flex-direction: column; gap: 6px; }
          label { font-size: .86rem; font-weight: 700; }
          input, select { width: 100%; padding: 11px 12px; border-radius: 14px; border: 1px solid var(--line); background: rgba(255,255,255,.86); color: var(--text); font: inherit; }
          .check { padding: 10px 12px; align-items: center; }
          .stage { display: flex; justify-content: space-between; gap: 12px; margin-top: 14px; }
          .stage-label, .report-wrap { margin-top: 6px; }
          .chart { display: flex; gap: 10px; align-items: flex-end; height: 210px; padding: 16px; }
          .bar { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; align-items: center; gap: 8px; }
          .bar span { width: 100%; border-radius: 14px 14px 6px 6px; background: linear-gradient(180deg, var(--accent-3) 0%, var(--accent) 100%); }
          .pie-panel { display: grid; place-items: center; padding: 16px; text-align: center; }
          .pie { width: 180px; height: 180px; border-radius: 50%; background: conic-gradient(var(--accent) 0 50%, var(--accent-3) 50% 72%, var(--warn) 72% 88%, rgba(93,82,72,.20) 88% 100%); box-shadow: inset 0 0 0 14px rgba(255,255,255,.68); }
          .log { background: var(--log-bg); color: var(--log-text); border-radius: 18px; padding: 14px; min-height: 340px; max-height: 460px; overflow: auto; font-family: Consolas, "Courier New", monospace; font-size: .87rem; }
          .log div { padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,.06); }
          table { width: 100%; border-collapse: collapse; overflow: hidden; }
          th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: .92rem; }
          th { background: rgba(255,255,255,.92); }
          .report-links { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
          .empty-note { padding: 12px 14px; border-radius: 16px; background: rgba(255,255,255,.70); border: 1px dashed var(--line); color: var(--muted); }
          @media (max-width: 1180px) {
            .layout, .hero-card, .dashboard-grid, .visual-grid, .lower-grid, .stats, .form-grid, .checks, .status-grid, .hero-meta { grid-template-columns: 1fr; }
            .topbar { grid-template-columns: 1fr; }
            .sidebar { border-right: none; border-bottom: 1px solid var(--line); }
            .session-list { max-height: 320px; }
          }
        CSS
      rescue StandardError
        ""
      end

      def client_script
        defaults_json = JSON.generate(default_config)
        <<~JAVASCRIPT
          const defaults = #{defaults_json};
          const state = { sessions: [], current: null, currentSession: null, dirty: false, autosaveTimer: null, refreshInFlight: false };
          const fields = ["name","target","mode","format","ports","threads","timeout","delay","scope","exclude","webhook-url","webhook-platform","shodan-key","monitor","memory","headless","verbose","adaptive-rate"];
          const themeKey = "asrfacet-web-theme";
          const el = (id) => document.getElementById(id);

          function escapeHtml(value) {
            return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[char] || char));
          }
          function parseJson(response) { return response.json().catch(() => ({})); }
          function relativeTime(value) {
            if (!value) return "never";
            const diff = Math.max(0, Date.now() - new Date(value).getTime());
            const mins = Math.floor(diff / 60000);
            if (mins < 1) return "just now";
            if (mins < 60) return `${mins}m ago`;
            const hours = Math.floor(mins / 60);
            if (hours < 24) return `${hours}h ago`;
            return `${Math.floor(hours / 24)}d ago`;
          }
          function statusClass(status) { return `pill ${String(status || "idle").toLowerCase()}`; }
          async function api(url, options = {}) {
            const response = await fetch(url, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
            return parseJson(response);
          }

          function setTheme(theme) {
            const safe = ["light", "dark", "grey"].includes(theme) ? theme : "light";
            document.documentElement.setAttribute("data-theme", safe);
            localStorage.setItem(themeKey, safe);
            el("theme-name").textContent = safe.charAt(0).toUpperCase() + safe.slice(1);
            ["light", "dark", "grey"].forEach((name) => el(`theme-${name}`).classList.toggle("active", name === safe));
          }

          function formData() {
            return {
              id: state.current,
              name: el("name").value.trim(),
              config: {
                target: el("target").value.trim(),
                mode: el("mode").value,
                format: el("format").value,
                ports: el("ports").value.trim(),
                threads: Number(el("threads").value || 50),
                timeout: Number(el("timeout").value || 10),
                delay: Number(el("delay").value || 0),
                scope: el("scope").value.trim(),
                exclude: el("exclude").value.trim(),
                webhook_url: el("webhook-url").value.trim(),
                webhook_platform: el("webhook-platform").value,
                shodan_key: el("shodan-key").value.trim(),
                monitor: el("monitor").checked,
                memory: el("memory").checked,
                headless: el("headless").checked,
                verbose: el("verbose").checked,
                adaptive_rate: el("adaptive-rate").checked
              }
            };
          }

          function fillForm(session) {
            const config = Object.assign({}, defaults, session?.config || {});
            el("name").value = session?.name || "Untitled session";
            el("target").value = config.target || "";
            el("mode").value = config.mode || "scan";
            el("format").value = config.format || "html";
            el("ports").value = config.ports || "top100";
            el("threads").value = config.threads || 50;
            el("timeout").value = config.timeout || 10;
            el("delay").value = config.delay || 0;
            el("scope").value = config.scope || "";
            el("exclude").value = config.exclude || "";
            el("webhook-url").value = config.webhook_url || "";
            el("webhook-platform").value = config.webhook_platform || "slack";
            el("shodan-key").value = config.shodan_key || "";
            el("monitor").checked = config.monitor !== false;
            el("memory").checked = config.memory !== false;
            el("headless").checked = config.headless === true;
            el("verbose").checked = config.verbose !== false;
            el("adaptive-rate").checked = config.adaptive_rate !== false;
            state.dirty = false;
          }

          function renderSessionList() {
            const container = el("session-list");
            el("meta-sessions").textContent = String(state.sessions.length);
            el("meta-reports").textContent = state.sessions.length > 0 ? "Ready" : "Awaiting";
            container.innerHTML = state.sessions.map((session) => `
              <div class="session ${session.id === state.current ? "active" : ""}" data-session-id="${escapeHtml(session.id || "")}">
                <strong>${escapeHtml(session.name || "Untitled session")}</strong>
                <div class="tiny muted" style="margin-top:6px">${escapeHtml(session.target || "No target yet")} | ${escapeHtml(session.mode || "scan")}</div>
                <div class="controls spread" style="margin-top:10px">
                  <span class="${statusClass(session.status)}">${escapeHtml(session.status || "idle")}</span>
                  <span class="tiny muted">${escapeHtml(relativeTime(session.updated_at))}</span>
                </div>
              </div>
            `).join("") || '<div class="empty-note">No saved sessions yet. Create one to begin building a recon workflow.</div>';
            Array.from(container.querySelectorAll("[data-session-id]")).forEach((node) => node.addEventListener("click", () => loadSession(node.getAttribute("data-session-id"))));
          }

          function renderBarChart(summary) {
            const max = Math.max(1, summary.subdomains || 0, summary.ips || 0, summary.open_ports || 0, summary.http_responses || 0, summary.findings || 0);
            const rows = [["Hosts", summary.subdomains || 0], ["IPs", summary.ips || 0], ["Ports", summary.open_ports || 0], ["Web", summary.http_responses || 0], ["Findings", summary.findings || 0]];
            el("bar-chart").innerHTML = rows.map(([label, value]) => `<div class="bar"><span style="height:${Math.max(18, Math.round((value / max) * 150))}px"></span><strong>${value}</strong><div class="tiny muted">${label}</div></div>`).join("");
          }

          function renderReports(session) {
            const artifacts = session?.artifacts || {};
            const links = [["CLI", "cli_report"], ["TXT", "txt_report"], ["HTML", "html_report"], ["JSON", "json_report"]].filter(([, key]) => Boolean(artifacts[key]));
            el("report-links").innerHTML = links.map(([label, key]) => `<a class="button secondary" target="_blank" rel="noopener" href="/reports/${encodeURIComponent(session.id)}/${key}">${label} report</a>`).join("") || '<div class="empty-note">Reports appear here after the first completed run.</div>';
          }

          function renderActivity(session) {
            const events = Array.isArray(session?.events) ? session.events.slice(-120) : [];
            el("activity-log").innerHTML = events.map((entry) => `<div>[${escapeHtml(entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "--:--:--")}] ${escapeHtml(entry.message || entry.type || "event")}</div>`).join("") || "<div>No activity yet. Save a session and start a run to stream progress here.</div>";
            el("activity-log").scrollTop = el("activity-log").scrollHeight;
          }

          function renderDetails(session) {
            const summary = session?.summary || {};
            const rows = [
              { item: "Scope posture", meaning: session?.config?.scope ? `Allowlist active: ${session.config.scope}` : "Primary target scope only.", recommendation: "Confirm exclusions before larger active runs." },
              { item: "Monitoring", meaning: session?.config?.monitor ? "Change tracking is enabled for drift analysis." : "Change tracking is disabled.", recommendation: session?.config?.monitor ? "Review the change summary after each run." : "Enable monitoring for repeat baselines." },
              { item: "Recon memory", meaning: session?.config?.memory ? "Known assets can be reused." : "Each run will re-check all assets.", recommendation: session?.config?.memory ? "Keep memory enabled for recurring targets." : "Enable memory to speed up repeat inventories." },
              { item: "Host coverage", meaning: `${summary.subdomains || 0} subdomains and ${summary.ips || 0} IPs were collected.`, recommendation: "Investigate high-signal hosts first and confirm ownership for shared infrastructure." },
              { item: "Service exposure", meaning: `${summary.open_ports || 0} open ports were recorded.`, recommendation: "Prioritize unusual ports and externally exposed management services." },
              { item: "Web exposure", meaning: `${summary.http_responses || 0} HTTP responses were fingerprinted.`, recommendation: "Open the HTML report to inspect technologies, routes, and captured artifacts." },
              { item: "Findings", meaning: `${summary.findings || 0} findings were generated.`, recommendation: "Validate critical and high findings first, then work through medium items." }
            ];
            el("detail-table").innerHTML = rows.map((row) => `<tr><td>${escapeHtml(row.item)}</td><td>${escapeHtml(row.meaning)}</td><td>${escapeHtml(row.recommendation)}</td></tr>`).join("");
          }

          function renderTopAssets(session) {
            const assets = Array.isArray(session?.payload?.top_assets) ? session.payload.top_assets.slice(0, 8) : [];
            el("top-assets-table").innerHTML = assets.map((asset) => `<tr><td>${escapeHtml(asset.host || "-")}</td><td>${escapeHtml(String(asset.total_score || 0))}</td><td>${escapeHtml(Array(asset.matched_rules || []).join(", ") || "Interesting exposure patterns detected.")}</td></tr>`).join("") || '<tr><td colspan="3" class="muted">Top assets appear after a completed run.</td></tr>';
          }

          function renderFindings(session) {
            const findings = Array.isArray(session?.payload?.store?.findings) ? session.payload.store.findings.slice(0, 8) : [];
            el("findings-table").innerHTML = findings.map((finding) => `<tr><td>${escapeHtml(String(finding.severity || "info").toUpperCase())}</td><td>${escapeHtml(finding.title || "Untitled finding")}</td><td>${escapeHtml(finding.host || "-")}</td></tr>`).join("") || '<tr><td colspan="3" class="muted">No findings recorded yet.</td></tr>';
          }

          function updateSummary(session) {
            const summary = Object.assign({ subdomains: 0, ips: 0, open_ports: 0, http_responses: 0, findings: 0 }, session?.summary || {});
            el("sum-subdomains").textContent = summary.subdomains || 0;
            el("sum-ips").textContent = summary.ips || 0;
            el("sum-ports").textContent = summary.open_ports || 0;
            el("sum-web").textContent = summary.http_responses || 0;
            el("sum-findings").textContent = summary.findings || 0;
            const currentStage = session?.current_stage || {};
            el("stage-name").textContent = currentStage.name ? `${currentStage.name} (${currentStage.phase || "working"})` : "Waiting for a run.";
            el("stage-phase").className = statusClass(session?.status);
            el("stage-phase").textContent = session?.status || "idle";
            el("status-pill").className = statusClass(session?.status);
            el("status-pill").textContent = session?.status || "idle";
            el("heartbeat-label").textContent = session?.last_heartbeat_at ? relativeTime(session.last_heartbeat_at) : "Idle";
            renderBarChart(summary);
            renderReports(session || {});
            renderActivity(session || {});
            renderDetails(session || {});
            renderTopAssets(session || {});
            renderFindings(session || {});
          }

          async function refreshSessions(preferredId, options = {}) {
            if (state.refreshInFlight) return;
            state.refreshInFlight = true;
            try {
              const data = await api("/api/sessions");
              state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
              renderSessionList();
              const nextId = preferredId || state.current || state.sessions[0]?.id;
              const shouldReload = options.reloadCurrent !== false && !state.dirty;
              if (nextId && shouldReload) await loadSession(nextId, false);
            } finally {
              state.refreshInFlight = false;
            }
          }

          async function loadSession(id, promptOnDirty = true) {
            if (!id) return;
            if (promptOnDirty && state.dirty) {
              const shouldSave = window.confirm("This session has unsaved changes. Press OK to save before switching, or Cancel to stay on the current session.");
              if (!shouldSave) return;
              await saveSession(true);
            }
            const data = await api(`/api/session?id=${encodeURIComponent(id)}`);
            state.currentSession = data.session || null;
            state.current = state.currentSession?.id || id;
            fillForm(state.currentSession || { config: defaults });
            updateSummary(state.currentSession || {});
            renderSessionList();
          }

          async function saveSession(silent = false) {
            const data = await api("/api/sessions", { method: "POST", body: JSON.stringify(formData()) });
            if (data.session) {
              state.currentSession = data.session;
              state.current = data.session.id;
              state.dirty = false;
              const existingIndex = state.sessions.findIndex((item) => item.id === data.session.id);
              const summary = {
                id: data.session.id,
                name: data.session.name,
                status: data.session.status,
                running: data.session.running,
                target: data.session.config?.target,
                mode: data.session.config?.mode,
                updated_at: data.session.updated_at,
                last_heartbeat_at: data.session.last_heartbeat_at,
                summary: data.session.summary || {},
                current_stage: data.session.current_stage || {},
                artifacts: data.session.artifacts || {},
                error: data.session.error
              };
              if (existingIndex >= 0) {
                state.sessions.splice(existingIndex, 1, summary);
              } else {
                state.sessions.unshift(summary);
              }
              renderSessionList();
              updateSummary(state.currentSession);
              if (!silent) window.alert("Session saved.");
            }
          }

          async function runSession() {
            if (!state.current) await saveSession(true);
            if (!state.current) {
              window.alert("Save a session with a target first.");
              return;
            }
            const response = await api(`/api/run?id=${encodeURIComponent(state.current)}`, { method: "POST" });
            if (!response.ok) {
              window.alert("This session is already running or could not be started.");
              return;
            }
            state.dirty = false;
            await loadSession(state.current, false);
          }

          function createSession() {
            state.current = null;
            state.currentSession = { name: "Untitled session", config: defaults };
            fillForm(state.currentSession);
            updateSummary(state.currentSession);
            state.dirty = true;
          }

          function saveDraftBeacon() {
            try {
              navigator.sendBeacon("/api/sessions", new Blob([JSON.stringify(formData())], { type: "application/json" }));
            } catch (_) {}
          }

          function markDirty() {
            state.dirty = true;
            clearTimeout(state.autosaveTimer);
            state.autosaveTimer = setTimeout(() => { saveSession(true).catch(() => null); }, 700);
          }

          function attachListeners() {
            fields.forEach((id) => {
              const node = el(id);
              const eventName = node && node.type === "checkbox" ? "change" : "input";
              node?.addEventListener(eventName, markDirty);
            });
            el("save-session").addEventListener("click", () => saveSession());
            el("run-session").addEventListener("click", () => runSession());
            el("new-session").addEventListener("click", () => createSession());
            el("refresh-sessions").addEventListener("click", () => refreshSessions(state.current));
            ["light", "dark", "grey"].forEach((name) => el(`theme-${name}`).addEventListener("click", () => setTheme(name)));
            window.addEventListener("beforeunload", (event) => {
              if (!state.dirty && !(state.currentSession && state.currentSession.running)) return;
              saveDraftBeacon();
              event.preventDefault();
              event.returnValue = "";
            });
            document.addEventListener("visibilitychange", () => {
              if (document.visibilityState === "hidden") saveDraftBeacon();
            });
          }

          async function bootstrap() {
            setTheme(localStorage.getItem(themeKey) || "light");
            const data = await api("/api/bootstrap");
            state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
            renderSessionList();
            attachListeners();
            if (state.sessions[0]?.id) {
              await loadSession(state.sessions[0].id, false);
            } else {
              createSession();
            }
            setInterval(() => { refreshSessions(state.current).catch(() => null); }, 2500);
          }

          bootstrap().catch(() => {
            el("activity-log").innerHTML = "<div>Unable to initialize the control panel.</div>";
          });
        JAVASCRIPT
      rescue StandardError
        ""
      end
    end
  end
end
