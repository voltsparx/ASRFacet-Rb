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

require "pastel"

module ASRFacet
  class DryRunPrinter
    def initialize(domain, options)
      @domain = domain
      @options = options
      @pastel = Pastel.new
    end

    def print
      lines = []
      lines << @pastel.bold.yellow("== DRY RUN - nothing will touch the network ==")
      lines << ""
      lines << @pastel.bold("Target:       ") + @domain
      lines << @pastel.bold("Threads:      ") + threads.to_s
      lines << @pastel.bold("Port range:   ") + ports
      lines << @pastel.bold("Memory:       ") + @options[:memory].to_s
      lines << @pastel.bold("Monitor:      ") + @options[:monitor].to_s
      lines << @pastel.bold("Stealth:      ") + stealth
      lines << @pastel.bold("Output:       ") + format_info
      lines << ""
      lines << @pastel.bold("Passive sources that would run:")
      active_sources.each { |source| lines << "  #{@pastel.green("+")} #{source}" }
      inactive_sources.each { |source| lines << "  #{@pastel.red("-")} #{source} (no API key)" }
      lines << ""
      lines << @pastel.bold("Estimated runtime: ") + estimate_time
      lines.join("\n")
    end

    private

    def threads
      @options[:threads] || 50
    end

    def ports
      @options[:ports] || "top100"
    end

    def stealth
      @options[:stealth] || "medium"
    end

    def format_info
      format = @options[:format] || "cli"
      output = @options[:output]
      output ? "#{format} -> #{output}" : format
    end

    def active_sources
      %w[crtsh hackertarget wayback rapiddns alienvault bufferover urlscan commoncrawl]
    end

    def inactive_sources
      key_store = ASRFacet::KeyStore.new
      %w[shodan virustotal securitytrails].reject { |source| key_store.get(source) }
    rescue ASRFacet::KeyStoreError
      %w[shodan virustotal securitytrails]
    end

    def estimate_time
      case threads
      when 0..25 then "5-10 minutes (cautious)"
      when 26..75 then "2-5 minutes (balanced)"
      else "1-3 minutes (aggressive)"
      end
    end
  end
end
