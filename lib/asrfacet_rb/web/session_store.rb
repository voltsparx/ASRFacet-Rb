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
      attr_reader :root

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
          summary: symbolize(payload[:summary] || {})
        )
      rescue StandardError
        nil
      end

      def mark_failed(id, message)
        append_event(id, type: "error", message: message.to_s)
        timestamp = Time.now.utc.iso8601
        update_session(
          id,
          status: "failed",
          running: false,
          error: message.to_s,
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
          config: {
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
            format: "html"
          },
          summary: {},
          artifacts: {},
          events: [],
          payload: {},
          error: nil,
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

        symbolize(JSON.parse(File.read(path)))
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
        if value.respond_to?(:to_h) && !value.is_a?(Hash)
          normalize(value.to_h)
        elsif value.is_a?(Hash)
          value.each_with_object({}) { |(key, nested), memo| memo[key.to_sym] = normalize(nested) }
        elsif value.is_a?(Array)
          value.map { |entry| normalize(entry) }
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
    end
  end
end
