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
require "uri"
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
        session = @session_store.fetch(request_param(req, "id").to_s)
        session ? respond_json(res, { session: session }) : respond_json(res, { error: "not_found" }, status: 404)
      rescue StandardError
        respond_json(res, { error: "lookup_failed" }, status: 500)
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
          error: item[:error],
          error_details: item[:error_details] || {},
          integrity: item[:integrity] || {}
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
