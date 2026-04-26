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

require "json"
require "time"
require "webrick"

module ASRFacet
  module Lab
    class TemplateServer
      DEFAULT_HOST = "127.0.0.1"
      DEFAULT_PORT = 9292
      attr_reader :host, :port

      TEMPLATES = {
        "headers" => "A page with intentionally weak security headers for HTTP fingerprinting validation.",
        "directory" => "A directory-listing style page with common artifact names.",
        "cors" => "An API route with permissive CORS headers for response inspection.",
        "javascript" => "A JavaScript-heavy page that exposes API-looking endpoints and placeholder token patterns.",
        "exposure" => "Common debug and metadata routes to validate path discovery."
      }.freeze

      def initialize(host: DEFAULT_HOST, port: DEFAULT_PORT, manage_signals: true)
        @host = host.to_s.strip.empty? ? DEFAULT_HOST : host.to_s.strip
        @port = port.to_i.positive? ? port.to_i : DEFAULT_PORT
        @manage_signals = manage_signals
        @server = nil
      rescue ASRFacet::Error, ArgumentError, NoMethodError, TypeError
        @host = DEFAULT_HOST
        @port = DEFAULT_PORT
        @manage_signals = manage_signals
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
        trap_signals if @manage_signals
        ASRFacet::Core::ThreadSafe.print_status("ASRFacet local lab listening on http://#{@host}:#{@port}")
        ASRFacet::Core::ThreadSafe.print_status("Use this only for safe local validation of the framework before real authorized targets.")
        @server.start
      rescue ASRFacet::Error, IOError, SystemCallError, ScriptError => e
        ASRFacet::Core::ThreadSafe.print_error("Lab startup failed: #{e.message}")
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
        @server.mount_proc("/") { |_req, res| html(res, index_page) }
        @server.mount_proc("/healthz") { |_req, res| health(res) }
        @server.mount_proc("/readyz") { |_req, res| readiness(res) }
        @server.mount_proc("/assets/app.js") { |_req, res| javascript(res, app_js) }
        @server.mount_proc("/app") { |_req, res| html(res, app_page) }
        @server.mount_proc("/browse/") { |_req, res| html(res, directory_listing_page) }
        @server.mount_proc("/admin") { |_req, res| html(res, admin_page) }
        @server.mount_proc("/metrics") { |_req, res| plain(res, "requests_total 42\nhealth_status 1\n") }
        @server.mount_proc("/debug/status") { |_req, res| json(res, { status: "debug-enabled", environment: "lab", note: "safe placeholder data only" }) }
        @server.mount_proc("/download/.env") { |_req, res| plain(res, "APP_ENV=lab\nDEMO_TOKEN=REDACTED_PLACEHOLDER\n") }
        @server.mount_proc("/api/v1/users") { |_req, res| json(res, { users: [{ id: 1, name: "lab-user" }] }) }
        @server.mount_proc("/graphql") { |_req, res| json(res, { data: { status: "graphql-lab" } }) }
        @server.mount_proc("/rest/audit") { |_req, res| json(res, { events: [{ id: "evt-1", action: "demo" }] }) }
        @server.mount_proc("/cors/profile") { |_req, res| cors_json(res, { profile: "demo-profile", scope: "lab-only" }) }
        @server.mount_proc("/.well-known/security.txt") { |_req, res| plain(res, "Contact: mailto:security@example.local\n") }
      rescue StandardError
        nil
      end

      def health(res)
        json(res, status_payload("ok"))
      rescue StandardError
        nil
      end

      def readiness(res)
        ready = !@server.nil?
        json(res, status_payload(ready ? "ready" : "not_ready"), status: ready ? 200 : 503)
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

      def index_page
        items = TEMPLATES.map { |name, description| "<li><strong>#{name}</strong>: #{description}</li>" }.join
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>ASRFacet Local Lab</title>
          </head>
          <body>
            <h1>ASRFacet Local Validation Lab</h1>
            <p>This local-only lab exposes safe placeholder surfaces so you can test the framework before real authorized targets.</p>
            <ul>#{items}</ul>
            <p>Useful routes: <code>/app</code>, <code>/browse/</code>, <code>/admin</code>, <code>/metrics</code>, <code>/debug/status</code>, <code>/download/.env</code>, <code>/cors/profile</code></p>
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body>ASRFacet Local Lab</body></html>"
      end

      def app_page
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>Lab SPA</title>
          </head>
          <body>
            <h1>Lab SPA Surface</h1>
            <p>This page loads a demo script with API-looking routes and placeholder secrets for discovery testing.</p>
            <script src="/assets/app.js"></script>
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body>Lab SPA</body></html>"
      end

      def directory_listing_page
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head><meta charset="utf-8"><title>Index of /browse/</title></head>
          <body>
            <h1>Index of /browse/</h1>
            <ul>
              <li><a href="/browse/backup.zip">backup.zip</a></li>
              <li><a href="/browse/config.old">config.old</a></li>
              <li><a href="/browse/reports/">reports/</a></li>
            </ul>
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body>Index of /browse/</body></html>"
      end

      def admin_page
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head><meta charset="utf-8"><title>Admin Portal</title></head>
          <body>
            <h1>Admin Portal</h1>
            <form action="/admin/login" method="post">
              <input type="text" name="username" placeholder="Username">
              <input type="password" name="password" placeholder="Password">
              <button type="submit">Login</button>
            </form>
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body>Admin Portal</body></html>"
      end

      def app_js
        <<~JAVASCRIPT
          window.labConfig = {
            apiBase: "/api/v1",
            graphql: "/graphql",
            auditTrail: "/rest/audit",
            placeholderToken: "PLACEHOLDER_TOKEN_PATTERN_ONLY",
            notes: "This lab contains no live credentials or real secrets."
          };
          fetch("/api/v1/users").then(() => null);
          fetch("/graphql", { method: "POST" }).then(() => null);
          fetch("/rest/audit", { method: "DELETE" }).then(() => null);
        JAVASCRIPT
      rescue StandardError
        "window.labConfig={};"
      end

      def html(res, body)
        res.status = 200
        res["Content-Type"] = "text/html; charset=utf-8"
        res.body = body.to_s
      rescue StandardError
        nil
      end

      def javascript(res, body)
        res.status = 200
        res["Content-Type"] = "application/javascript; charset=utf-8"
        res.body = body.to_s
      rescue StandardError
        nil
      end

      def plain(res, body)
        res.status = 200
        res["Content-Type"] = "text/plain; charset=utf-8"
        res.body = body.to_s
      rescue StandardError
        nil
      end

      def json(res, payload, status: 200)
        res.status = status
        res["Content-Type"] = "application/json; charset=utf-8"
        res.body = JSON.pretty_generate(payload)
      rescue StandardError
        nil
      end

      def cors_json(res, payload)
        res.status = 200
        res["Content-Type"] = "application/json; charset=utf-8"
        res["Access-Control-Allow-Origin"] = "*"
        res["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
        res.body = JSON.pretty_generate(payload)
      rescue StandardError
        nil
      end

      def status_payload(status)
        {
          service: "lab",
          status: status,
          host: @host,
          port: @port,
          templates: TEMPLATES.keys,
          timestamp: Time.now.utc.iso8601
        }
      rescue StandardError
        { service: "lab", status: status }
      end
    end
  end
end
