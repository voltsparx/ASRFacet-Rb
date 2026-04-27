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

module ASRFacet
  module Plugins
    class Engine
      def initialize(selection: nil, logger: nil, user_dir: File.join(Dir.pwd, "plugins"))
        @selection = selection
        @logger = logger
        @user_dir = user_dir
        load_user_plugins
      rescue StandardError
        @selection = selection
        @logger = logger
        @user_dir = user_dir
      end

      def available
        ObjectSpace.each_object(Class).select do |klass|
          klass < ASRFacet::Plugins::Base &&
            klass != ASRFacet::Plugins::Base &&
            klass.respond_to?(:plugin_family) &&
            klass.plugin_family == :session
        end.sort_by { |klass| [klass.priority, klass.plugin_name] }
      rescue StandardError
        []
      end

      def names
        available.map(&:plugin_name)
      rescue StandardError
        []
      end

      def catalog(mode: nil, category: nil, search: nil)
        ASRFacet::Extensions::AttachableCatalog.filter(
          available.map(&:metadata),
          mode: mode,
          category: category,
          search: search
        )
      rescue StandardError
        []
      end

      def find(name)
        normalized = name.to_s.strip.downcase
        catalog.find { |entry| entry[:name].to_s == normalized || Array(entry[:aliases]).include?(normalized) }
      rescue StandardError
        nil
      end

      def resolve(selection: @selection, mode: nil, category: nil, search: nil)
        plan = ASRFacet::Extensions::AttachableCatalog.resolve(
          available.map(&:metadata),
          selection: selection,
          mode: mode,
          category: category,
          search: search
        )
        plan.merge(classes: resolve_classes(plan[:selected]))
      rescue StandardError
        { available: [], selected: [], excluded: [], unknown: [], include_tokens: [], exclude_tokens: [], classes: [] }
      end

      def enabled(mode: nil)
        resolve(mode: mode)[:classes]
      rescue StandardError
        []
      end

      def apply(context)
        runtime = symbolize(context)
        runtime[:plugin_trace] ||= []
        runtime[:extension_resolution] ||= {}
        plan = resolve(mode: runtime[:mode])
        runtime[:extension_resolution][:plugins] = plan.reject { |key, _value| key == :classes }
        Array(plan[:unknown]).each do |token|
          runtime[:plugin_trace] << { name: token, status: "unknown_selector" }
        end
        Array(plan[:classes]).each do |plugin_class|
          instance = plugin_class.new
          next unless instance.respond_to?(:apply)

          instance.apply(runtime)
          runtime[:plugin_trace] << { name: plugin_class.plugin_name, status: "applied" }
        rescue ASRFacet::PluginError => e
          runtime[:plugin_trace] << { name: plugin_class.plugin_name, status: "failed", error: e.message }
          runtime[:store]&.add(:plugin_errors, { plugin: plugin_class.plugin_name, error: e.message })
          @logger&.warn(event: :plugin_apply_error, plugin: plugin_class.plugin_name, error: e.message)
        end
        runtime
      rescue StandardError
        context
      end

      private

      def load_user_plugins
        return unless Dir.exist?(@user_dir)

        Dir.glob(File.join(@user_dir, "**", "*.rb")).sort.each { |path| require path }
      rescue StandardError
        nil
      end

      def resolve_classes(metadata_entries)
        names = Array(metadata_entries).map { |entry| entry[:name].to_s }
        available.select { |klass| names.include?(klass.plugin_name.to_s) }
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
        value
      end
    end
  end
end
