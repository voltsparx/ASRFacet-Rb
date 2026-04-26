# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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

require "open3"
require "rbconfig"

module ASRFacet
  module Scanner
    module Platform
      module_function

      def windows?
        host_os.match?(/mswin|mingw|cygwin/i)
      rescue StandardError
        false
      end

      def macos?
        host_os.match?(/darwin/i)
      rescue StandardError
        false
      end

      def linux?
        host_os.match?(/linux/i)
      rescue StandardError
        false
      end

      def elevated?
        return windows_admin? if windows?
        return false unless Process.respond_to?(:uid)

        Process.uid.zero?
      rescue StandardError
        false
      end

      def command_available?(command_name)
        return false if command_name.to_s.strip.empty?

        lookup = windows? ? ["where", command_name.to_s] : ["sh", "-lc", "command -v #{shell_escape(command_name.to_s)}"]
        _stdout, _stderr, status = Open3.capture3(*lookup)
        status.success?
      rescue StandardError
        false
      end

      def nping_available?
        command_available?("nping")
      end

      def sudo_available?
        !windows? && command_available?("sudo")
      end

      def powershell_available?
        windows? && command_available?("powershell")
      end

      def elevation_supported?
        return powershell_available? if windows?

        sudo_available?
      rescue StandardError
        false
      end

      def privilege_label
        return "Run as Administrator" if windows?

        "sudo"
      rescue StandardError
        "elevated privileges"
      end

      def host_label
        return "Windows" if windows?
        return "macOS" if macos?
        return "Linux" if linux?

        host_os
      rescue StandardError
        "unknown"
      end

      def raw_backend_requirements
        return "Nping with Npcap support and an elevated Administrator shell" if windows?

        "Nping and an elevated shell such as sudo"
      rescue StandardError
        "a raw-capable backend and elevated privileges"
      end

      def host_os
        RbConfig::CONFIG["host_os"].to_s
      rescue StandardError
        ""
      end

      def shell_escape(text)
        text.to_s.gsub("'", %q('\\'')) # shell-safe single-quote escape
      rescue StandardError
        text.to_s
      end

      def windows_admin?
        script = "[Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()" \
                 ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        stdout, _stderr, status = Open3.capture3("powershell", "-NoProfile", "-Command", script)
        status.success? && stdout.to_s.strip.casecmp("true").zero?
      rescue StandardError
        false
      end
    end
  end
end
