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

require "csv"
require "fileutils"
require "json"
require "time"
require_relative "asset_graph"

module ASRFacet
  module Intelligence
    class SessionManager
      WORKSPACE_FILES = %w[graph.json session.json sources.log dns.log scan.log].freeze

      attr_reader :root

      def initialize(root: File.expand_path("~/.asrfacet_rb/workspaces"))
        @root = root
        @mutex = Mutex.new
        FileUtils.mkdir_p(@root)
      end

      def create(target)
        @mutex.synchronize do
          FileUtils.mkdir_p(workspace_path(target))
          graph = AssetGraph.new(target, root: @root)
          graph.persist_async.join
          session = default_session(target, graph.stats)
          write_json(session_path(target), session)
          ensure_workspace_files(target)
        end
        load(target)
      end

      def load(target)
        return nil unless Dir.exist?(workspace_path(target))

        graph = AssetGraph.new(target, root: @root).load_from_disk
        session = read_json(session_path(target)) || default_session(target, graph.stats)
        session[:last_active] = Time.now.utc.iso8601
        session[:source_counts] = source_counts(graph)
        session[:asset_counts] = graph.stats[:asset_types]
        write_json(session_path(target), session)

        {
          target: target.to_s,
          workspace_path: workspace_path(target),
          session_path: session_path(target),
          graph_path: graph_path(target),
          session: session,
          graph: graph.to_h
        }
      end

      def list
        Dir.children(@root).filter_map do |entry|
          target = entry.tr("_", ".")
          loaded = load(target)
          next if loaded.nil?

          loaded[:session].merge(target: loaded[:target], workspace_path: loaded[:workspace_path])
        end.sort_by { |session| session[:last_active].to_s }.reverse
      rescue Errno::ENOENT
        []
      end

      def delete(target)
        path = workspace_path(target)
        return false unless Dir.exist?(path)

        FileUtils.rm_rf(path)
        true
      end

      def export(target, format:)
        workspace = load(target)
        raise ASRFacet::Error, "Workspace not found: #{target}" if workspace.nil?

        timestamp = Time.now.utc.strftime("%Y%m%d%H%M%S")
        case format.to_s.downcase
        when "json"
          export_json(target, workspace, timestamp)
        when "csv"
          export_csv(target, workspace, timestamp)
        else
          raise ASRFacet::ParseError, "Unsupported export format: #{format}"
        end
      end

      def resume?(target)
        workspace = load(target)
        return false if workspace.nil?

        %w[active running paused].include?(workspace.dig(:session, :status).to_s)
      end

      private

      def export_json(target, workspace, timestamp)
        path = File.join(workspace_path(target), "workspace_export_#{timestamp}.json")
        payload = {
          target: workspace[:target],
          exported_at: Time.now.utc.iso8601,
          session: workspace[:session],
          graph: workspace[:graph]
        }
        write_json(path, payload)
        path
      end

      def export_csv(target, workspace, timestamp)
        path = File.join(workspace_path(target), "workspace_export_#{timestamp}.csv")
        CSV.open(path, "wb") do |csv|
          csv << %w[record_type id from_id to_id type value source found_at confidence properties]
          Array(workspace.dig(:graph, :nodes)).each do |asset|
            csv << [
              "asset",
              asset[:id],
              nil,
              nil,
              asset[:type],
              asset[:value],
              asset[:source],
              asset[:found_at],
              asset[:confidence],
              JSON.generate(asset[:properties] || {})
            ]
          end
          Array(workspace.dig(:graph, :edges)).each do |relation|
            csv << [
              "relation",
              nil,
              relation[:from_id],
              relation[:to_id],
              relation[:type],
              nil,
              relation[:source],
              relation[:found_at],
              nil,
              JSON.generate(relation[:properties] || {})
            ]
          end
        end
        path
      end

      def source_counts(graph)
        counts = Hash.new(0)
        Array(graph.nodes).each { |asset| counts[asset[:source].to_s] += 1 unless asset[:source].to_s.empty? }
        Array(graph.edges).each { |relation| counts[relation[:source].to_s] += 1 unless relation[:source].to_s.empty? }
        counts.sort.to_h
      end

      def default_session(target, graph_stats)
        timestamp = Time.now.utc.iso8601
        {
          target: target.to_s,
          started_at: timestamp,
          last_active: timestamp,
          status: "active",
          source_counts: {},
          asset_counts: graph_stats[:asset_types] || {}
        }
      end

      def workspace_path(target)
        File.join(@root, safe_target(target))
      end

      def graph_path(target)
        File.join(workspace_path(target), "graph.json")
      end

      def session_path(target)
        File.join(workspace_path(target), "session.json")
      end

      def ensure_workspace_files(target)
        WORKSPACE_FILES.each do |name|
          path = File.join(workspace_path(target), name)
          next if File.exist?(path)

          File.write(path, name.end_with?(".json") ? "{}" : "")
        end
      end

      def write_json(path, payload)
        File.write(path, JSON.pretty_generate(payload))
      end

      def read_json(path)
        return nil unless File.file?(path)

        JSON.parse(File.read(path), symbolize_names: true)
      rescue JSON::ParserError
        nil
      end

      def safe_target(target)
        cleaned = target.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_").tr(".", "_")
        cleaned.empty? ? "workspace" : cleaned
      end
    end
  end
end
