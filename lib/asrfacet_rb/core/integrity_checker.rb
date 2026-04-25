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
require "rbconfig"
require "yaml"

module ASRFacet
  module Core
    class IntegrityChecker
      REQUIRED_PATHS = [
        "bin/asrfacet-rb",
        "bin/asrfrb",
        "lib/asrfacet_rb.rb",
        "lib/asrfacet_rb/version.rb",
        "config/default.yml",
        "wordlists/subdomains_small.txt",
        "wordlists/paths_common.txt"
      ].freeze

      OPTIONAL_PATHS = [
        "man/asrfacet-rb.1",
        "man/asrfrb.1",
        "README.md"
      ].freeze

      class << self
        def check(app_root: default_app_root, output_root: nil)
          root = File.expand_path(app_root.to_s)
          report = {
            checked_at: Time.now.utc.iso8601,
            app_root: root,
            output_root: resolve_output_root(output_root),
            status: "ok",
            summary: "ASRFacet-Rb integrity checks passed.",
            issues: [],
            recommendations: []
          }

          REQUIRED_PATHS.each do |relative_path|
            next if File.exist?(File.join(root, relative_path))

            add_issue(
              report,
              severity: "critical",
              code: "missing_required_path",
              path: File.join(root, relative_path),
              summary: "A required framework file is missing.",
              details: "#{relative_path} could not be found under the application root.",
              recommendation: "Repair or reinstall the framework so the missing runtime file is restored."
            )
          end

          OPTIONAL_PATHS.each do |relative_path|
            next if File.exist?(File.join(root, relative_path))

            add_issue(
              report,
              severity: "warning",
              code: "missing_optional_path",
              path: File.join(root, relative_path),
              summary: "An optional framework file is missing.",
              details: "#{relative_path} was not found. Core scanning can continue, but a support surface may be incomplete.",
              recommendation: "Refresh the install if you expect the optional documentation or man page to be present."
            )
          end

          validate_config_file(report, root)
          validate_wordlists(report, root)
          validate_output_directory(report)
          validate_ruby_runtime(report)
          finalize(report)
        rescue StandardError => e
          {
            checked_at: Time.now.utc.iso8601,
            app_root: File.expand_path(app_root.to_s),
            output_root: resolve_output_root(output_root),
            status: "critical",
            summary: "ASRFacet-Rb could not complete its own integrity check.",
            issues: [
              {
                severity: "critical",
                code: "integrity_checker_failure",
                path: nil,
                summary: "The framework could not inspect itself safely.",
                details: e.message.to_s,
                recommendation: "Reinstall or update the framework, then run the verification flow again."
              }
            ],
            recommendations: ["Reinstall or update the framework, then run the verification flow again."]
          }
        end

        def critical?(report)
          symbolize(report).dig(:status).to_s == "critical"
        rescue StandardError
          false
        end

        private

        def default_app_root
          File.expand_path(File.join(__dir__, "..", "..", ".."))
        rescue StandardError
          Dir.pwd
        end

        def resolve_output_root(output_root)
          configured = output_root.to_s.strip
          configured = ASRFacet::Config.fetch("output", "directory").to_s if configured.empty?
          configured = "~/.asrfacet_rb/output" if configured.to_s.strip.empty?
          File.expand_path(configured)
        rescue StandardError
          File.expand_path("~/.asrfacet_rb/output")
        end

        def validate_config_file(report, root)
          path = File.join(root, "config", "default.yml")
          return unless File.file?(path)

          YAML.safe_load(File.read(path), permitted_classes: [Symbol], aliases: true)
        rescue StandardError => e
          add_issue(
            report,
            severity: "critical",
            code: "invalid_config",
            path: path,
            summary: "The default framework configuration could not be parsed.",
            details: e.message.to_s,
            recommendation: "Repair config/default.yml or reinstall the framework so the packaged configuration is valid YAML."
          )
        end

        def validate_wordlists(report, root)
          configured_lists = symbolize(config_for_root(root)).fetch(:wordlists, {})
          configured_lists.each do |name, relative_path|
            next if relative_path.to_s.strip.empty?

            absolute = File.expand_path(relative_path.to_s, root)
            next if File.file?(absolute)

            add_issue(
              report,
              severity: "critical",
              code: "missing_wordlist",
              path: absolute,
              summary: "A configured wordlist is missing.",
              details: "The #{name} wordlist points to #{relative_path}, but that file could not be found.",
              recommendation: "Restore the missing wordlist or update the configuration before running discovery commands."
            )
          end
        rescue StandardError => e
          add_issue(
            report,
            severity: "warning",
            code: "wordlist_validation_failed",
            path: nil,
            summary: "The framework could not validate its configured wordlists.",
            details: e.message.to_s,
            recommendation: "Review the wordlist paths in the packaged config and the user config."
          )
        end

        def validate_output_directory(report)
          root = report[:output_root].to_s
          FileUtils.mkdir_p(root)

          probe_dir = File.join(root, ".integrity")
          FileUtils.mkdir_p(probe_dir)
          probe_file = File.join(probe_dir, "write-test.tmp")
          File.write(probe_file, "ok")
          File.delete(probe_file) if File.file?(probe_file)
          Dir.rmdir(probe_dir) if Dir.exist?(probe_dir)
        rescue StandardError => e
          add_issue(
            report,
            severity: "critical",
            code: "output_not_writable",
            path: report[:output_root],
            summary: "The configured output directory is not writable.",
            details: e.message.to_s,
            recommendation: "Fix the output directory permissions or change the output root in ~/.asrfacet_rb/config.yml."
          )
        end

        def validate_ruby_runtime(report)
          version = Gem::Version.new(RUBY_VERSION)
          minimum = Gem::Version.new("3.2.0")
          return unless version < minimum

          add_issue(
            report,
            severity: "critical",
            code: "ruby_version_unsupported",
            path: RbConfig.ruby,
            summary: "The current Ruby runtime is older than the supported minimum.",
            details: "Detected Ruby #{RUBY_VERSION}, but ASRFacet-Rb requires Ruby 3.2 or newer.",
            recommendation: "Upgrade Ruby to 3.2+ and rerun the framework."
          )
        rescue StandardError
          nil
        end

        def add_issue(report, severity:, code:, path:, summary:, details:, recommendation:)
          report[:issues] << {
            severity: severity,
            code: code,
            path: path,
            summary: summary,
            details: details,
            recommendation: recommendation
          }
          report[:recommendations] << recommendation unless recommendation.to_s.strip.empty?
        rescue StandardError
          nil
        end

        def finalize(report)
          report[:recommendations] = Array(report[:recommendations]).uniq
          severities = Array(report[:issues]).map { |issue| issue[:severity].to_s }
          report[:status] =
            if severities.include?("critical")
              "critical"
            elsif severities.include?("warning")
              "warning"
            else
              "ok"
            end

          report[:summary] =
            case report[:status]
            when "critical"
              "ASRFacet-Rb found blocking integrity problems and should be repaired before active use."
            when "warning"
              "ASRFacet-Rb found non-blocking integrity issues. The framework can still run, but some surfaces may be incomplete."
            else
              "ASRFacet-Rb integrity checks passed."
            end

          report
        rescue StandardError
          report
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

        def config_for_root(root)
          path = File.join(root, "config", "default.yml")
          return {} unless File.file?(path)

          YAML.safe_load(File.read(path), permitted_classes: [Symbol], aliases: true) || {}
        rescue StandardError
          {}
        end
      end
    end
  end
end
