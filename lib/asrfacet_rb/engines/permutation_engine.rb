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

require "set"

module ASRFacet::Engines
  class PermutationEngine
    PREFIXES = %w[
      api dev staging test mail vpn cdn admin portal dashboard beta
      internal corp prod backup old new www2 secure static assets media
      img auth login app cloud git jenkins ci
    ].freeze

    SUFFIXES = %w[
      1 2 01 02 -dev -test -api -v2 -old -new -backup -prod -staging
    ].freeze

    def generate(domain, known_subdomains = [])
      results = Set.new
      labels = known_subdomains.map { |entry| extract_label(entry, domain) }.compact.uniq

      PREFIXES.each do |prefix|
        results << "#{prefix}.#{domain}"
      end

      labels.each do |label|
        PREFIXES.each do |prefix|
          results << "#{prefix}.#{label}.#{domain}"
          results << "#{label}-#{prefix}.#{domain}"
          results << "#{prefix}-#{label}.#{domain}"
        end

        SUFFIXES.each do |suffix|
          results << "#{label}#{suffix}.#{domain}"
        end
      end

      results.delete(domain)
      results.to_a.sort
    rescue StandardError
      []
    end

    private

    def extract_label(hostname, domain)
      host = hostname.to_s.downcase
      return nil unless host.end_with?(".#{domain}")

      label = host.sub(/\.#{Regexp.escape(domain)}\z/, "")
      return nil if label.empty?

      label.split(".").first
    rescue StandardError
      nil
    end
  end
end
