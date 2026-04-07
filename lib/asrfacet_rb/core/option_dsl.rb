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
  module Core
    module OptionDSL
      def self.included(base)
        base.extend(ClassMethods)
      rescue StandardError
        nil
      end

      module ClassMethods
        def option(name, type:, required:, default: nil, desc:)
          option_definitions[name.to_sym] = {
            type: type.to_sym,
            required: required,
            default: default,
            desc: desc
          }
        rescue StandardError
          nil
        end

        def option_definitions
          @option_definitions ||= inherited_option_definitions
        rescue StandardError
          {}
        end

        def validate_options!(given)
          merged = option_definitions.each_with_object({}) do |(key, definition), memo|
            memo[key] = given.key?(key) ? given[key] : definition[:default]
          end
          missing = option_definitions.select { |key, definition| definition[:required] && blank?(merged[key]) }.keys
          raise ArgumentError, "Missing required options: #{missing.join(', ')}" unless missing.empty?

          merged
        rescue StandardError => e
          raise e if e.is_a?(ArgumentError)

          {}
        end

        private

        def inherited_option_definitions
          return {} unless superclass.respond_to?(:option_definitions)

          superclass.option_definitions.dup
        rescue StandardError
          {}
        end

        def blank?(value)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        rescue StandardError
          false
        end
      end
    end
  end
end
