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
  module UI
    class ExtensionConsoleState
      SUPPORTED_MODES = %w[scan passive dns ports portscan enum intel].freeze
      COMMAND_TO_MODE = {
        "scan" => "scan",
        "s" => "scan",
        "sc" => "scan",
        "passive" => "passive",
        "p" => "passive",
        "pa" => "passive",
        "dns" => "dns",
        "d" => "dns",
        "dn" => "dns",
        "ports" => "ports",
        "pt" => "ports",
        "po" => "ports",
        "portscan" => "portscan",
        "enum" => "enum",
        "intel" => "intel"
      }.freeze

      def initialize(active_mode: "scan")
        @active_mode = normalize_mode(active_mode)
        @mode_specs = SUPPORTED_MODES.each_with_object({}) do |mode, memo|
          memo[mode] = { plugins: "", filters: "" }
        end
      rescue StandardError
        @active_mode = "scan"
        @mode_specs = {}
      end

      attr_reader :active_mode

      def use_mode(mode)
        normalized = normalize_mode(mode)
        return false if normalized.empty?

        @active_mode = normalized
        true
      rescue StandardError
        false
      end

      def mode_for_command(command)
        COMMAND_TO_MODE[command.to_s.strip.downcase]
      rescue StandardError
        nil
      end

      def spec_for(kind, mode: @active_mode)
        selection_for(mode)[kind.to_sym].to_s
      rescue StandardError
        ""
      end

      def set(kind, spec, mode: @active_mode)
        normalized_mode = normalize_mode(mode)
        return failure("Unsupported mode: #{mode}") if normalized_mode.empty?

        plan = resolve(kind, spec, mode: normalized_mode)
        return failure(plan[:unknown_message]) if plan[:unknown].any?

        selection_for(normalized_mode)[kind.to_sym] = normalize_spec(spec)
        success(plan)
      rescue StandardError => e
        failure(e.message)
      end

      def add(kind, spec, mode: @active_mode)
        merged = [spec_for(kind, mode: mode), normalize_spec(spec)].reject(&:empty?).join(",")
        set(kind, merged, mode: mode)
      rescue StandardError => e
        failure(e.message)
      end

      def remove(kind, spec, mode: @active_mode)
        tokens = normalize_spec(spec).split(",").map(&:strip).reject(&:empty?).map do |token|
          token.start_with?("-", "!") ? token : "-#{token}"
        end
        merged = [spec_for(kind, mode: mode), tokens.join(",")].reject(&:empty?).join(",")
        set(kind, merged, mode: mode)
      rescue StandardError => e
        failure(e.message)
      end

      def review(mode: @active_mode)
        normalized_mode = normalize_mode(mode)
        {
          mode: normalized_mode,
          plugins: resolve(:plugins, spec_for(:plugins, mode: normalized_mode), mode: normalized_mode),
          filters: resolve(:filters, spec_for(:filters, mode: normalized_mode), mode: normalized_mode)
        }
      rescue StandardError
        { mode: normalized_mode || "scan", plugins: {}, filters: {} }
      end

      def flags_for_command(command, explicit_plugins: false, explicit_filters: false)
        mode = mode_for_command(command)
        return [] if mode.nil?

        flags = []
        plugin_spec = spec_for(:plugins, mode: mode)
        filter_spec = spec_for(:filters, mode: mode)
        flags.concat(["--plugins", plugin_spec]) unless explicit_plugins || plugin_spec.empty?
        flags.concat(["--filters", filter_spec]) unless explicit_filters || filter_spec.empty?
        flags
      rescue StandardError
        []
      end

      private

      def resolve(kind, spec, mode:)
        engine = kind.to_sym == :filters ? ASRFacet::Filters::Engine.new(selection: spec) : ASRFacet::Plugins::Engine.new(selection: spec)
        plan = engine.resolve(mode: mode)
        label = kind.to_sym == :filters ? "filter" : "plugin"
        plan[:unknown_message] = "Unknown #{label} selectors: #{Array(plan[:unknown]).join(', ')}"
        plan
      rescue StandardError
        { selected: [], excluded: [], unknown: [spec.to_s], unknown_message: "Unable to resolve #{kind} selectors." }
      end

      def selection_for(mode)
        @mode_specs[mode] ||= { plugins: "", filters: "" }
      rescue StandardError
        { plugins: "", filters: "" }
      end

      def normalize_mode(mode)
        normalized = mode.to_s.strip.downcase
        return normalized if SUPPORTED_MODES.include?(normalized)

        ""
      rescue StandardError
        ""
      end

      def normalize_spec(spec)
        spec.to_s.split(",").map { |entry| entry.to_s.strip.downcase }.reject(&:empty?).uniq.join(",")
      rescue StandardError
        ""
      end

      def success(plan)
        { ok: true, plan: plan }
      rescue StandardError
        { ok: true, plan: {} }
      end

      def failure(message)
        { ok: false, error: message.to_s }
      rescue StandardError
        { ok: false, error: "Unknown console extension error." }
      end
    end
  end
end
