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
  module Extensions
    class SessionAugmentor
      def initialize(logger: nil)
        @logger = logger
      end

      def apply(target:, store:, graph: nil, options: {}, mode: :scan, scope: nil, execution: {})
        normalized_mode = mode.to_s.downcase
        runtime = {
          target: target.to_s,
          store: store || ASRFacet::ResultStore.new,
          graph: graph,
          options: symbolize(options),
          mode: normalized_mode.to_sym,
          scope: scope,
          execution: symbolize(execution),
          summary: store.respond_to?(:summary) ? store.summary : {}
        }
        runtime = ASRFacet::Plugins::Engine.new(selection: runtime.dig(:options, :plugins), logger: @logger).apply(runtime)
        runtime[:summary] = runtime[:store].summary if runtime[:store].respond_to?(:summary)
        runtime = ASRFacet::Filters::Engine.new(selection: runtime.dig(:options, :filters), logger: @logger).apply(runtime)
        runtime[:summary] = runtime[:store].summary if runtime[:store].respond_to?(:summary)
        runtime
      rescue StandardError
        {
          target: target.to_s,
          store: store,
          graph: graph,
          options: symbolize(options),
          mode: mode.to_s.downcase.to_sym,
          scope: scope,
          execution: symbolize(execution),
          summary: store.respond_to?(:summary) ? store.summary : {}
        }
      end

      private

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
