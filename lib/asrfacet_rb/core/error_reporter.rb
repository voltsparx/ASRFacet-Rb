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

require "time"

module ASRFacet
  module Core
    module ErrorReporter
      module_function

      def build(engine:, error:, isolated: true, context: nil, timestamp: Time.now.utc.iso8601)
        exception = error.is_a?(StandardError) ? error : nil
        message = exception ? exception.message.to_s : error.to_s
        formatted_context = context.to_s.strip
        details = formatted_context.empty? ? message : "#{formatted_context}: #{message}"
        error_class = exception&.class&.name.to_s

        {
          engine: engine.to_s,
          summary: summary_for(engine, message, isolated: isolated),
          reason: message,
          details: details,
          error_class: error_class.empty? ? nil : error_class,
          isolated: isolated,
          recommendation: recommendation_for(engine, message, error_class, isolated: isolated),
          timestamp: timestamp
        }
      rescue StandardError
        {
          engine: engine.to_s,
          summary: "ASRFacet-Rb recorded a failure but could not fully describe it.",
          reason: error.to_s,
          details: error.to_s,
          error_class: nil,
          isolated: isolated,
          recommendation: "Re-run the command with --verbose and review the stored TXT or HTML report for the failure trail.",
          timestamp: timestamp
        }
      end

      def recommendation_for(engine, message, error_class = nil, isolated: true)
        text = [engine, message, error_class].compact.join(" ").downcase

        return "Repair or update the framework installation and restore the missing files before retrying the run." if text.include?("integrity") || text.include?("corrupt")
        return "Check file permissions and restore the missing file or directory, then retry the command." if text.include?("no such file") || text.include?("cannot find") || text.include?("missing")
        return "Increase --timeout, reduce --threads, or retry against a more responsive target window." if text.include?("timeout") || text.include?("execution expired")
        return "Reduce request pressure with --delay, keep adaptive rate control enabled, and try again after the cooldown." if text.include?("429") || text.include?("rate limit") || text.include?("circuit open")
        return "Review --scope and --exclude so the target stays authorized and reachable for this run." if text.include?("scope")
        return "Confirm DNS resolution, target spelling, and network reachability before retrying." if text.include?("socket") || text.include?("name or service not known") || text.include?("getaddrinfo") || text.include?("connection refused")
        return "Review TLS reachability and certificate handling. If the service is intentionally self-signed, confirm the expected transport path." if text.include?("ssl") || text.include?("certificate")
        return "Inspect config/default.yml and ~/.asrfacet_rb/config.yml for invalid YAML or unexpected overrides." if text.include?("config") || text.include?("yaml")
        return "Read the failure trail in the stored reports and rerun with --verbose so the affected engine can be narrowed down." if isolated

        "The run stopped before completion. Review the failure details, verify the framework install, and rerun once the blocking issue is fixed."
      rescue StandardError
        "Review the stored error details and rerun with --verbose for more context."
      end

      def summary_for(engine, message, isolated: true)
        component = humanize_engine(engine)
        if isolated
          "#{component} hit a recoverable problem and ASRFacet-Rb continued with fault isolation."
        elsif message.to_s.downcase.include?("integrity")
          "ASRFacet-Rb stopped because the framework integrity check found a blocking problem."
        else
          "#{component} stopped the run before completion."
        end
      rescue StandardError
        isolated ? "ASRFacet-Rb isolated a recoverable failure." : "ASRFacet-Rb stopped because of a blocking failure."
      end

      def humanize_engine(engine)
        label = engine.to_s.tr("_", " ").strip
        label.empty? ? "The framework" : label.split.map(&:capitalize).join(" ")
      rescue StandardError
        "The framework"
      end
    end
  end
end
