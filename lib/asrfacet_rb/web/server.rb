# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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

require "fileutils"
require "json"
require "time"
require "uri"
require "webrick"

module ASRFacet
  module Web
    class Server
      DEFAULT_HOST = "127.0.0.1"
      DEFAULT_PORT = 4567
      attr_reader :host, :port

      def initialize(host: DEFAULT_HOST, port: DEFAULT_PORT, session_store: nil, session_runner: nil, manage_signals: true)
        @host = host.to_s.strip.empty? ? DEFAULT_HOST : host.to_s.strip
        @port = port.to_i.positive? ? port.to_i : DEFAULT_PORT
        @session_store = session_store || ASRFacet::Web::SessionStore.new
        @session_runner = session_runner || ASRFacet::Web::SessionRunner.new(session_store: @session_store)
        @manage_signals = manage_signals
        @server = nil
      rescue ASRFacet::Error, ArgumentError, NoMethodError, TypeError
        @host = DEFAULT_HOST
        @port = DEFAULT_PORT
        @session_store = session_store || ASRFacet::Web::SessionStore.new
        @session_runner = session_runner || ASRFacet::Web::SessionRunner.new(session_store: @session_store)
        @manage_signals = manage_signals
        @server = nil
      end

      def start
        FileUtils.mkdir_p(@session_store.root.to_s)
        FileUtils.mkdir_p(reports_root.to_s)
        @server = WEBrick::HTTPServer.new(
          BindAddress: @host,
          Port: @port,
          AccessLog: [],
          Logger: WEBrick::Log.new($stderr, WEBrick::Log::FATAL)
        )
        mount_routes
        trap_signals if @manage_signals
        ASRFacet::Core::ThreadSafe.print_status("Web session control panel listening on http://#{@host}:#{@port}")
        ASRFacet::Core::ThreadSafe.print_status("Saved sessions are stored in #{@session_store.root}")
        @server.start
      rescue ASRFacet::Error, IOError, SystemCallError, ScriptError => e
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
        @server.mount_proc("/healthz") { |_req, res| handle_health(res) }
        @server.mount_proc("/readyz") { |_req, res| handle_readiness(res) }
        @server.mount_proc("/api/bootstrap") { |_req, res| handle_bootstrap(res) }
        @server.mount_proc("/api/sessions") { |req, res| handle_sessions(req, res) }
        @server.mount_proc("/api/session") { |req, res| handle_session_lookup(req, res) }
        @server.mount_proc("/api/session/clone") { |req, res| handle_session_clone(req, res) }
        @server.mount_proc("/api/session/stop") { |req, res| handle_session_stop(req, res) }
        @server.mount_proc("/api/run") { |req, res| handle_run(req, res) }
        @server.mount_proc("/reports") { |req, res| handle_reports(req, res) }
        @server.mount_proc("/assets/icon") { |_req, res| handle_icon(res) }
        @server.mount_proc("/assets/dashboard.css") { |_req, res| handle_dashboard_css(res) }
        @server.mount_proc("/assets/dashboard.js") { |_req, res| handle_dashboard_js(res) }
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

      def handle_health(res)
        respond_json(res, health_payload(status: "ok"))
      rescue StandardError
        respond_json(res, { error: "health_failed" }, status: 500)
      end

      def handle_readiness(res)
        ready = readiness_ok?
        respond_json(res, health_payload(status: ready ? "ready" : "not_ready"), status: ready ? 200 : 503)
      rescue StandardError
        respond_json(res, { error: "readiness_failed" }, status: 500)
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
            capabilities: capability_payload,
            sessions: @session_store.list_sessions.map { |session| summarize_session(session) },
            about: ASRFacet::UI::About.plain_text,
            first_run: !ASRFacet::UI::FirstRunGuide.seen?,
            first_run_guide: ASRFacet::UI::FirstRunGuide.guide_lines,
            docs: documentation_payload
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
        method = req.respond_to?(:request_method) ? req.request_method.to_s.upcase : "GET"
        return handle_session_delete(req, res) if method == "DELETE"
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless method == "GET"

        session = @session_store.fetch(request_param(req, "id").to_s)
        session ? respond_json(res, { session: session }) : respond_json(res, { error: "not_found" }, status: 404)
      rescue StandardError
        respond_json(res, { error: "lookup_failed" }, status: 500)
      end

      def handle_session_clone(req, res)
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless req.request_method == "POST"

        session_id = request_param(req, "id").to_s
        duplicated = @session_store.duplicate(session_id)
        return respond_json(res, { error: "not_found" }, status: 404) if duplicated.nil?

        respond_json(res, { session: duplicated })
      rescue StandardError
        respond_json(res, { error: "clone_failed" }, status: 500)
      end

      def handle_session_stop(req, res)
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless req.request_method == "POST"

        session_id = request_param(req, "id").to_s
        return respond_json(res, { error: "not_found" }, status: 404) if @session_store.fetch(session_id).nil?

        if @session_runner.respond_to?(:stop) && @session_runner.stop(session_id)
          respond_json(res, { ok: true, session_id: session_id, status: "stopped" })
        else
          respond_json(res, { ok: false, error: "not_running" }, status: 409)
        end
      rescue StandardError
        respond_json(res, { error: "stop_failed" }, status: 500)
      end

      def handle_run(req, res)
        return respond_json(res, { error: "method_not_allowed" }, status: 405) unless req.request_method == "POST"

        session_id = request_param(req, "id").to_s
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
        session = @session_store.fetch(session_id)
        path = session.to_h.dig(:artifacts, key.to_sym).to_s
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

      def handle_dashboard_css(res)
        content = styles_css
        return respond_json(res, { error: "asset_not_found" }, status: 404) if content.to_s.empty?

        res.status = 200
        res["Cache-Control"] = "no-store"
        res["Content-Type"] = "text/css; charset=utf-8"
        res.body = content
      rescue StandardError
        respond_json(res, { error: "asset_failed" }, status: 500)
      end

      def handle_dashboard_js(res)
        content = client_script
        return respond_json(res, { error: "asset_not_found" }, status: 404) if content.to_s.empty?

        res.status = 200
        res["Cache-Control"] = "no-store"
        res["Content-Type"] = "application/javascript; charset=utf-8"
        res.body = content
      rescue StandardError
        respond_json(res, { error: "asset_failed" }, status: 500)
      end

      def normalize_session_payload(payload)
        item = symbolize(payload)
        item[:name] = item[:name].to_s.strip.empty? ? "Untitled session" : item[:name].to_s.strip
        item[:config] = ASRFacet::Web::SessionStore.normalize_config(default_config.merge(symbolize(item[:config] || {})))
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
          error: item[:error],
          error_details: item[:error_details] || {},
          integrity: item[:integrity] || {},
          stop_requested: item[:stop_requested] == true
        }
      rescue StandardError
        {}
      end

      def default_config
        ASRFacet::Web::SessionStore.default_config
      rescue StandardError
        {}
      end

      def capability_payload
        plugin_engine = ASRFacet::Plugins::Engine.new(selection: "all")
        filter_engine = ASRFacet::Filters::Engine.new(selection: "all")
        {
          modes: ASRFacet::Web::SessionStore::VALID_MODES,
          formats: ASRFacet::Web::SessionStore::VALID_FORMATS,
          scan_types: ASRFacet::Web::SessionStore::VALID_SCAN_TYPES,
          raw_backends: ASRFacet::Web::SessionStore::VALID_RAW_BACKENDS,
          plugins: plugin_engine.names,
          filters: filter_engine.names,
          plugins_catalog: plugin_engine.catalog,
          filters_catalog: filter_engine.catalog,
          selector_help: ASRFacet::Extensions::AttachableCatalog.selector_help,
          scan_timings: (0..5).to_a,
          port_presets: %w[top100 top1000 top65535 common],
          webhook_platforms: ASRFacet::Web::SessionStore::VALID_WEBHOOK_PLATFORMS,
          session_actions: %w[save run clone stop delete],
          platform: ASRFacet::Scanner::Platform.host_label,
          nping_available: ASRFacet::Scanner::Platform.nping_available?,
          elevation_supported: ASRFacet::Scanner::Platform.elevation_supported?,
          raw_scan_requirements: ASRFacet::Scanner::Platform.raw_backend_requirements
        }
      rescue StandardError
        {}
      end

      def handle_session_delete(req, res)
        session_id = request_param(req, "id").to_s
        deleted = @session_store.delete(session_id)
        deleted ? respond_json(res, { ok: true, session_id: session_id }) : respond_json(res, { error: "not_found" }, status: 404)
      rescue StandardError
        respond_json(res, { error: "delete_failed" }, status: 500)
      end

      def reports_root
        File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
      rescue StandardError
        File.expand_path("~/.asrfacet_rb/output")
      end

      def readiness_ok?
        !@server.nil? && File.directory?(@session_store.root.to_s) && File.directory?(reports_root.to_s)
      rescue StandardError
        false
      end

      def health_payload(status:, status_code: nil)
        {
          service: "web",
          status: status,
          status_code: status_code || (status == "ready" || status == "ok" ? 200 : 503),
          host: @host,
          port: @port,
          sessions_root: @session_store.root.to_s,
          reports_root: reports_root,
          timestamp: Time.now.utc.iso8601
        }
      rescue StandardError
        { service: "web", status: status }
      end

      def framework_icon_path
        primary = File.expand_path("web_assets/asrfacet-rb-icon.png", __dir__)
        return primary if File.file?(primary)

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

      def request_param(req, key)
        key_name = key.to_s
        from_query = req.query[key_name].to_s
        return from_query unless from_query.empty?

        query_string = req.query_string.to_s
        if query_string.empty?
          request_uri = req.request_uri
          query_string = request_uri.query.to_s if request_uri.respond_to?(:query)
          query_string = request_uri.to_s.split("?", 2).last.to_s if query_string.empty? && request_uri.to_s.include?("?")
        end
        return nil if query_string.empty?

        URI.decode_www_form(query_string).to_h[key_name]
      rescue StandardError
        nil
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
        return "application/json; charset=utf-8" if path.end_with?(".sarif")
        return "application/pdf" if path.end_with?(".pdf")
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if path.end_with?(".docx")
        return "text/csv; charset=utf-8" if path.end_with?(".csv")

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

      def documentation_payload
        docs_root = File.expand_path("../../../docs", __dir__)
        Dir.glob(File.join(docs_root, "*.md")).sort.map do |path|
          {
            slug: File.basename(path, ".md"),
            title: File.basename(path, ".md").split(/[_-]/).map(&:capitalize).join(" "),
            content: File.read(path)
          }
        end
      rescue StandardError
        []
      end

      def dashboard_html
        asset_template("dashboard.html")
      rescue StandardError
        "<!DOCTYPE html><html><body><h1>ASRFacet-Rb</h1></body></html>"
      end

      def styles_css
        asset_template("dashboard.css", "__ASRFACET_COLOR_VARIABLES__" => ASRFacet::Colors.css_variables)
      rescue StandardError
        ""
      end

      def client_script
        asset_template("dashboard.js", "__DEFAULT_CONFIG_JSON__" => JSON.generate(default_config))
      rescue StandardError
        ""
      end

      def asset_template(name, replacements = {})
        content = File.read(File.join(web_assets_root, name))
        replacements.each do |needle, replacement|
          content = content.gsub(needle.to_s, replacement.to_s)
        end
        content
      rescue StandardError
        ""
      end

      def web_assets_root
        File.expand_path("web_assets", __dir__)
      rescue StandardError
        __dir__
      end
    end
  end
end
