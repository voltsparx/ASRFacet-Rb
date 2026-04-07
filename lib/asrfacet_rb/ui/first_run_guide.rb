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

module ASRFacet
  module UI
    module FirstRunGuide
      module_function

      def maybe_print(command_args = [])
        return false unless interactive_stdout?
        return false if seen?

        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.print_good("Welcome to ASRFacet-Rb. This appears to be your first run.")
        guide_lines(command_args).each do |line|
          ASRFacet::Core::ThreadSafe.puts("  #{line}")
        end
        ASRFacet::Core::ThreadSafe.puts("")
        mark_seen
        true
      rescue StandardError
        false
      end

      def seen?
        File.file?(marker_path)
      rescue StandardError
        true
      end

      def mark_seen
        FileUtils.mkdir_p(File.dirname(marker_path))
        File.write(marker_path, Time.now.utc.iso8601)
        true
      rescue StandardError
        false
      end

      def guide_lines(_command_args = [])
        [
          "Use `asrfacet-rb help`, `asrfacet-rb about`, or `asrfacet-rb manual workflow` to orient yourself.",
          "Start with a safe passive or scoped run before broad active validation.",
          "Examples:",
          "asrfacet-rb passive example.com",
          "asrfacet-rb scan example.com --scope example.com,*.example.com --exclude dev.example.com --monitor --memory",
          "asrfacet-rb --web-session",
          "asrfacet-rb lab",
          "Stored reports live under ~/.asrfacet_rb/output/ and web drafts live under ~/.asrfacet_rb/web_sessions/."
        ]
      rescue StandardError
        []
      end

      def marker_path
        File.expand_path("~/.asrfacet_rb/.first_run_seen")
      rescue StandardError
        ".asrfacet_rb_first_run"
      end

      def interactive_stdout?
        $stdout.tty?
      rescue StandardError
        false
      end
    end
  end
end
