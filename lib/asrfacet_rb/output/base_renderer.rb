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

require "fileutils"
require "time"

module ASRFacet
  module Output
    class BaseRenderer
      attr_reader :store, :target, :options

      def initialize(result_store, target, options = {})
        @store = result_store
        @target = target
        @options = options
      end

      def render(_output_path)
        raise NotImplementedError, "#{self.class}#render must be implemented"
      end

      protected

      def timestamp
        Time.now.strftime("%Y-%m-%d %H:%M:%S UTC")
      end

      def iso_timestamp
        Time.now.iso8601
      end

      def version
        ASRFacet::VERSION
      end

      def report_title
        "ASRFacet-Rb Recon Report - #{@target}"
      end

      def severity_order
        {
          "critical" => 0,
          "high" => 1,
          "medium" => 2,
          "low" => 3,
          "informational" => 4
        }
      end

      def sorted_findings
        Array(@store.findings).sort_by do |finding|
          severity_order[finding[:severity].to_s.downcase] || 99
        end
      end

      def write!(path, content)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, content, encoding: "UTF-8")
      end

      def log_success(format, path)
        puts "[ok] #{format} report written -> #{path}"
      end

      def log_error(format, message)
        warn "[error] #{format} render failed: #{message}"
      end
    end
  end
end
