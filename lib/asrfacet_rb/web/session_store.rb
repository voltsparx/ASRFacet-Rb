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
require "securerandom"
require "time"

module ASRFacet
  module Web
    class SessionStore
      HEARTBEAT_STALE_SECONDS = 15
      VALID_MODES = %w[scan passive dns ports portscan].freeze
      VALID_FORMATS = %w[cli json html txt csv pdf docx all sarif].freeze
      VALID_SCAN_TYPES = %w[connect syn udp ack fin null xmas window maimon ping service].freeze
      VALID_WEBHOOK_PLATFORMS = %w[slack discord].freeze
      DEFAULT_CONFIG = {
        mode: "scan",
        target: "",
        ports: "top100",
        threads: 50,
        timeout: 10,
        scope: "",
        exclude: "",
        monitor: true,
        memory: true,
        headless: false,
        verbose: true,
        delay: 0,
        adaptive_rate: true,
        format: "html",
        webhook_url: "",
        webhook_platform: "slack",
        shodan_key: "",
        scan_type: "connect",
        scan_timing: 3,
        scan_version: false,
        scan_os: false,
        scan_intensity: 7
      }.freeze

      attr_reader :root

      class << self
        def default_config
          deep_dup(DEFAULT_CONFIG)
        end

        def normalize_config(config)
          item = symbolize(config || {})
          {
            mode: normalize_mode(item[:mode]),
            target: item[:target].to_s.strip,
            ports: normalize_ports(item[:ports]),
            threads: bounded_integer(item[:threads], 50, min: 1, max: 1_000),
            timeout: bounded_integer(item[:timeout], 10, min: 1, max: 300),
            scope: item[:scope].to_s.strip,
            exclude: item[:exclude].to_s.strip,
            monitor: normalize_boolean(item[:monitor], default: true),
            memory: normalize_boolean(item[:memory], default: true),
            headless: normalize_boolean(item[:headless], default: false),
            verbose: normalize_boolean(item[:verbose], default: true),
            delay: bounded_integer(item[:delay], 0, min: 0, max: 600_000),
            adaptive_rate: normalize_boolean(item[:adaptive_rate], default: true),
            format: normalize_format(item[:format]),
            webhook_url: item[:webhook_url].to_s.strip,
            webhook_platform: normalize_webhook_platform(item[:webhook_platform]),
            shodan_key: item[:shodan_key].to_s.strip,
            scan_type: normalize_scan_type(item[:scan_type]),
            scan_timing: bounded_integer(item[:scan_timing], 3, min: 0, max: 5),
            scan_version: normalize_boolean(item[:scan_version], default: false),
            scan_os: normalize_boolean(item[:scan_os], default: false),
            scan_intensity: bounded_integer(item[:scan_intensity], 7, min: 0, max: 9)
          }
        rescue StandardError
          default_config
        end

        private

        def normalize_mode(value)
          mode = value.to_s.strip.downcase
          VALID_MODES.include?(mode) ? mode : DEFAULT_CONFIG[:mode]
        end

        def normalize_format(value)
          format = value.to_s.strip.downcase
          VALID_FORMATS.include?(format) ? format : DEFAULT_CONFIG[:format]
        end

        def normalize_scan_type(value)
          scan_type = value.to_s.strip.downcase
          VALID_SCAN_TYPES.include?(scan_type) ? scan_type : DEFAULT_CONFIG[:scan_type]
        end

        def normalize_webhook_platform(value)
          platform = value.to_s.strip.downcase
          VALID_WEBHOOK_PLATFORMS.include?(platform) ? platform : DEFAULT_CONFIG[:webhook_platform]
        end

        def normalize_ports(value)
          cleaned = value.to_s.strip.downcase
          return DEFAULT_CONFIG[:ports] if cleaned.empty?

          cleaned
        end

        def bounded_integer(value, fallback, min:, max:)
          parsed = Integer(value)
          [[parsed, min].max, max].min
        rescue StandardError
          fallback
        end

        def normalize_boolean(value, default:)
          return default if value.nil?
          return value if value == true || value == false

          case value.to_s.strip.downcase
          when "1", "true", "yes", "on" then true
          when "0", "false", "no", "off" then false
          else
            default
          end
        end

        def symbolize(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, nested), memo|
              memo[key.to_sym] = symbolize(nested)
            end
          when Array
            value.map { |entry| symbolize(entry) }
          else
            value
          end
        rescue StandardError
          {}
        end

        def deep_dup(value)
          case value
          when Hash
            value.each_with_object({}) { |(key, nested), memo| memo[key] = deep_dup(nested) }
          when Array
            value.map { |entry| deep_dup(entry) }
          else
            value
          end
        end
      end

      def initialize(root: File.expand_path("~/.asrfacet_rb/web_sessions"))
        @root = root
        @mutex = Mutex.new
        FileUtils.mkdir_p(@root)
        recover_interrupted_sessions!
      rescue StandardError
        @root = File.expand_path("~/.asrfacet_rb/web_sessions")
        @mutex = Mutex.new
      end

      def list_sessions
        @mutex.synchronize do
          Dir.glob(File.join(@root, "*.json")).filter_map do |path|
            load_file(path)
          end.sort_by { |session| session[:updated_at].to_s }.reverse
        end
      rescue StandardError
        []
      end

      def fetch(id)
        return nil if id.to_s.strip.empty?

        @mutex.synchronize { load_file(path_for(id)) }
      rescue StandardError
        nil
      end

      def create_or_update(attrs = {})
        data = symbolize(attrs)
        session = default_session.merge(data)
        session[:id] = data[:id].to_s.empty? ? SecureRandom.hex(8) : data[:id].to_s
        existing = fetch(session[:id]) || {}
        session = deep_merge(existing, session)
        session[:name] = session[:name].to_s.strip.empty? ? "Untitled session" : session[:name].to_s.strip
        session[:config] = self.class.normalize_config(session[:config] || {})
        session[:updated_at] = Time.now.utc.iso8601
        @mutex.synchronize do
          atomic_write(path_for(session[:id]), JSON.pretty_generate(normalize(session)))
          session
        end
      rescue StandardError
        nil
      end

      def mark_running(id, meta = {})
        timestamp = Time.now.utc.iso8601
        update_session(
          id,
          status: "running",
          running: true,
          last_run_started_at: timestamp,
          last_heartbeat_at: timestamp,
          error: nil,
          current_stage: nil,
          run_meta: symbolize(meta)
        )
      rescue StandardError
        nil
      end

      def update_heartbeat(id, meta = {})
        update_session(
          id,
          running: true,
          last_heartbeat_at: Time.now.utc.iso8601,
          run_meta: symbolize(meta)
        )
      rescue StandardError
        nil
      end

      def mark_completed(id, payload)
        timestamp = Time.now.utc.iso8601
        update_session(
          id,
          status: "completed",
          running: false,
          last_run_completed_at: timestamp,
          last_heartbeat_at: timestamp,
          payload: normalize_payload(payload),
          artifacts: symbolize(payload[:artifacts] || {}),
          summary: symbolize(payload[:summary] || {}),
          integrity: symbolize(payload[:integrity] || payload.dig(:execution, :integrity) || {}),
          error_details: {}
        )
      rescue StandardError
        nil
      end

      def mark_failed(id, message)
        details = normalize_failure(message)
        append_event(id, type: "error", message: details[:summary], data: details)
        timestamp = Time.now.utc.iso8601
        update_session(
          id,
          status: "failed",
          running: false,
          error: details[:summary],
          error_details: details,
          last_run_completed_at: timestamp,
          last_heartbeat_at: timestamp
        )
      rescue StandardError
        nil
      end

      def update_stage(id, index:, name:, phase:, snapshot: {})
        append_event(
          id,
          type: "stage",
          stage_index: index,
          stage_name: name,
          phase: phase.to_s,
          snapshot: symbolize(snapshot)
        )
        update_session(
          id,
          current_stage: {
            index: index,
            name: name,
            phase: phase.to_s,
            snapshot: symbolize(snapshot),
            updated_at: Time.now.utc.iso8601
          }
        )
      rescue StandardError
        nil
      end

      def append_event(id, event)
        @mutex.synchronize do
          session = load_file(path_for(id)) || default_session.merge(id: id.to_s)
          events = Array(session[:events]).last(399)
          events << symbolize(event).merge(timestamp: Time.now.utc.iso8601)
          session[:events] = events
          session[:updated_at] = Time.now.utc.iso8601
          atomic_write(path_for(id), JSON.pretty_generate(normalize(session)))
          session
        end
      rescue StandardError
        nil
      end

      def update_session(id, attrs = {})
        @mutex.synchronize do
          session = load_file(path_for(id)) || default_session.merge(id: id.to_s)
          session = deep_merge(session, symbolize(attrs))
          session[:updated_at] = Time.now.utc.iso8601
          session[:last_heartbeat_at] = Time.now.utc.iso8601 if session[:running]
          atomic_write(path_for(id), JSON.pretty_generate(normalize(session)))
          session
        end
      rescue StandardError
        nil
      end

      def recover_interrupted_sessions!
        list_sessions.each do |session|
          next unless session[:status].to_s == "running"
          next unless stale_session?(session)

          append_event(session[:id], type: "system", message: "Session recovered after an unclean shutdown. The previous run was marked interrupted.")
          update_session(session[:id], status: "interrupted", running: false, error: "The host process stopped before the run completed.")
        end
      rescue StandardError
        nil
      end

      private

      def default_session
        {
          id: nil,
          name: "Untitled session",
          status: "idle",
          running: false,
          config: self.class.default_config,
          summary: {},
          integrity: {},
          artifacts: {},
          events: [],
          payload: {},
          error: nil,
          error_details: {},
          last_heartbeat_at: nil,
          created_at: Time.now.utc.iso8601,
          updated_at: Time.now.utc.iso8601
        }
      rescue StandardError
        {}
      end

      def normalize_payload(payload)
        normalize(payload)
      rescue StandardError
        {}
      end

      def path_for(id)
        File.join(@root, "#{id}.json")
      rescue StandardError
        File.join(@root, "session.json")
      end

      def load_file(path)
        return nil unless File.file?(path)

        hydrate_session(symbolize(JSON.parse(File.read(path))))
      rescue StandardError
        nil
      end

      def atomic_write(path, content)
        tmp = "#{path}.tmp"
        File.write(tmp, content)
        FileUtils.mv(tmp, path, force: true)
      rescue StandardError
        nil
      end

      def deep_merge(base, extra)
        base.merge(extra) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge(old_value, new_value)
          else
            new_value
          end
        end
      rescue StandardError
        extra
      end

      def normalize(value)
        if value.is_a?(Hash)
          value.each_with_object({}) { |(key, nested), memo| memo[key.to_sym] = normalize(nested) }
        elsif value.is_a?(Array)
          value.map { |entry| normalize(entry) }
        elsif value.nil?
          nil
        elsif value.respond_to?(:to_h) && !value.is_a?(Hash)
          normalize(value.to_h)
        else
          value
        end
      rescue StandardError
        value.to_s
      end

      def symbolize(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize(nested)
          end
        when Array
          value.map { |entry| symbolize(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end

      def stale_session?(session)
        heartbeat_at = parse_time(session[:last_heartbeat_at])
        return true if heartbeat_at.nil?

        pid = session.to_h.dig(:run_meta, :process_id).to_i
        stale = (Time.now.utc - heartbeat_at) > HEARTBEAT_STALE_SECONDS
        return false unless stale
        return true unless pid.positive?

        !process_alive?(pid)
      rescue StandardError
        true
      end

      def parse_time(value)
        return nil if value.to_s.strip.empty?

        Time.parse(value.to_s)
      rescue StandardError
        nil
      end

      def process_alive?(pid)
        Process.kill(0, pid)
        true
      rescue Errno::EPERM
        true
      rescue StandardError
        false
      end

      def normalize_failure(message)
        details = symbolize(message)
        return details if details.is_a?(Hash) && details[:summary]

        {
          summary: message.to_s,
          reason: message.to_s,
          details: message.to_s,
          recommendation: "Review the session activity log and rerun with a healthier framework or target configuration."
        }
      rescue StandardError
        {
          summary: message.to_s,
          reason: message.to_s,
          details: message.to_s,
          recommendation: "Review the session activity log and rerun with a healthier framework or target configuration."
        }
      end

      def hydrate_session(session)
        item = symbolize(session)
        item[:config] = self.class.normalize_config(item[:config] || {})
        item[:events] = [] if item[:events].is_a?(Hash) && item[:events].empty?
        item[:error] = nil if item[:error].is_a?(Hash) && item[:error].empty?
        item[:last_heartbeat_at] = nil if item[:last_heartbeat_at].is_a?(Hash) && item[:last_heartbeat_at].empty?
        item
      rescue StandardError
        session
      end
    end
  end
end
