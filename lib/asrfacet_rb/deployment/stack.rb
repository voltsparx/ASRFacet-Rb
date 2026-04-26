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
require "net/http"
require "time"
require "timeout"
require "uri"

module ASRFacet
  module Deployment
    class Stack
      DEFAULT_STARTUP_TIMEOUT = 30

      attr_reader :web_host, :web_port, :lab_host, :lab_port, :manifest_path

      def initialize(
        web_host: ASRFacet::Web::Server::DEFAULT_HOST,
        web_port: ASRFacet::Web::Server::DEFAULT_PORT,
        lab_host: ASRFacet::Lab::TemplateServer::DEFAULT_HOST,
        lab_port: ASRFacet::Lab::TemplateServer::DEFAULT_PORT,
        with_lab: true,
        public: false,
        manifest_path: nil,
        startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        web_server_class: ASRFacet::Web::Server,
        lab_server_class: ASRFacet::Lab::TemplateServer
      )
        @public = public
        @with_lab = with_lab
        @web_host = normalized_host(web_host, public: public)
        @web_port = normalized_port(web_port, ASRFacet::Web::Server::DEFAULT_PORT)
        @lab_host = normalized_host(lab_host, public: public)
        @lab_port = normalized_port(lab_port, ASRFacet::Lab::TemplateServer::DEFAULT_PORT)
        @manifest_path = manifest_path.to_s.strip.empty? ? default_manifest_path : File.expand_path(manifest_path.to_s)
        @startup_timeout = startup_timeout.to_i.positive? ? startup_timeout.to_i : DEFAULT_STARTUP_TIMEOUT
        @web_server = web_server_class.new(host: @web_host, port: @web_port, manage_signals: false)
        @lab_server = @with_lab ? lab_server_class.new(host: @lab_host, port: @lab_port, manage_signals: false) : nil
        @threads = []
        @running = false
        @stopping = false
        @signal_handlers = {}
      end

      def start(wait: true)
        FileUtils.mkdir_p(File.dirname(@manifest_path))
        install_signal_handlers
        start_components
        wait_until_ready
        manifest = write_manifest(status: "ready")
        print_ready_banner(manifest)
        if wait
          @running = true
          sleep 0.25 while @running
        end
        manifest
      rescue ASRFacet::Error, IOError, JSON::ParserError, Net::OpenTimeout, Net::ReadTimeout, SystemCallError => e
        write_manifest(status: "failed", error: e.message)
        raise ASRFacet::Error, "Deployment startup failed: #{e.message}"
      ensure
        stop if wait
      end

      def stop
        return if @stopping

        @stopping = true
        @running = false
        @lab_server&.shutdown
        @web_server.shutdown
        @threads.each { |thread| thread.join(2) if thread&.alive? }
        write_manifest(status: "stopped")
      rescue ASRFacet::Error, IOError, SystemCallError
        nil
      ensure
        restore_signal_handlers
      end

      private

      def start_components
        @threads << Thread.new { @web_server.start }
        @threads << Thread.new { @lab_server.start } if @lab_server
      rescue ThreadError => e
        raise ASRFacet::Error, "Unable to start deployment threads: #{e.message}"
      end

      def wait_until_ready
        wait_for_endpoint(web_url("/readyz"))
        wait_for_endpoint(lab_url("/readyz")) if @lab_server
      end

      def wait_for_endpoint(url)
        deadline = Time.now + @startup_timeout
        last_error = nil

        while Time.now < deadline
          begin
            response = Net::HTTP.start(URI(url).host, URI(url).port, open_timeout: 2, read_timeout: 2) do |http|
              http.get(URI(url).request_uri)
            end
            return true if response.code.to_i == 200

            last_error = "HTTP #{response.code}"
          rescue IOError, SystemCallError, Timeout::Error => e
            last_error = e.message
          end
          sleep 0.25
        end

        raise ASRFacet::Error, "Timed out waiting for #{url} (last error: #{last_error || 'none'})"
      end

      def install_signal_handlers
        %w[INT TERM].each do |signal|
          @signal_handlers[signal] = Signal.trap(signal) do
            ASRFacet::Core::ThreadSafe.print_warning("Received #{signal}, shutting down deployment stack...")
            stop
          end
        rescue ArgumentError, Errno::EINVAL, SystemCallError
          nil
        end
      end

      def restore_signal_handlers
        @signal_handlers.each do |signal, handler|
          Signal.trap(signal, handler)
        rescue ArgumentError, Errno::EINVAL, SystemCallError
          nil
        end
        @signal_handlers.clear
      end

      def write_manifest(status:, error: nil)
        payload = manifest_payload(status: status, error: error)
        File.write(@manifest_path, JSON.pretty_generate(payload))
        payload
      rescue IOError, SystemCallError => e
        raise ASRFacet::Error, "Unable to write deployment manifest: #{e.message}"
      end

      def manifest_payload(status:, error: nil)
        {
          status: status,
          public: @public,
          started_at: Time.now.utc.iso8601,
          manifest_path: @manifest_path,
          services: {
            web: {
              enabled: true,
              bind: "#{@web_host}:#{@web_port}",
              url: web_url,
              health: web_url("/healthz"),
              ready: web_url("/readyz")
            },
            lab: {
              enabled: !@lab_server.nil?,
              bind: "#{@lab_host}:#{@lab_port}",
              url: lab_url,
              health: lab_url("/healthz"),
              ready: lab_url("/readyz")
            }
          },
          error: error
        }
      rescue StandardError
        { status: status, error: error }
      end

      def print_ready_banner(manifest)
        web = manifest.dig(:services, :web) || manifest.dig("services", "web") || {}
        lab = manifest.dig(:services, :lab) || manifest.dig("services", "lab") || {}
        ASRFacet::Core::ThreadSafe.print_good("ASRFacet deployment stack is ready.")
        ASRFacet::Core::ThreadSafe.puts("  Web UI: #{web[:url] || web['url']}")
        ASRFacet::Core::ThreadSafe.puts("  Web health: #{web[:health] || web['health']}")
        if lab[:enabled] || lab["enabled"]
          ASRFacet::Core::ThreadSafe.puts("  Lab: #{lab[:url] || lab['url']}")
          ASRFacet::Core::ThreadSafe.puts("  Lab health: #{lab[:health] || lab['health']}")
        end
        ASRFacet::Core::ThreadSafe.puts("  Manifest: #{@manifest_path}")
      rescue StandardError
        nil
      end

      def web_url(path = "")
        "http://#{reachable_host(@web_host)}:#{@web_port}#{path}"
      end

      def lab_url(path = "")
        "http://#{reachable_host(@lab_host)}:#{@lab_port}#{path}"
      end

      def reachable_host(host)
        return "127.0.0.1" if host == "0.0.0.0"

        host
      rescue StandardError
        "127.0.0.1"
      end

      def normalized_host(host, public:)
        return "0.0.0.0" if public

        value = host.to_s.strip
        value.empty? ? "127.0.0.1" : value
      rescue StandardError
        public ? "0.0.0.0" : "127.0.0.1"
      end

      def normalized_port(port, fallback)
        value = port.to_i
        value.positive? ? value : fallback
      rescue StandardError
        fallback
      end

      def default_manifest_path
        File.expand_path("~/.asrfacet_rb/runtime/deploy.json")
      rescue StandardError
        File.expand_path("./deploy.json")
      end
    end
  end
end
