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

require "set"

module ASRFacet
  class PermutationEngine
    PREFIXES = %w[
      dev staging prod api api-v2 api-v3 test qa uat
      admin internal corp vpn mail smtp ftp cdn static
      assets img images beta alpha preview sandbox
    ].freeze

    SUFFIXES = %w[
      -dev -staging -prod -test -api -v2 -v3 -old -new
      -internal -corp -backup -legacy -2 -3
    ].freeze

    def initialize(discovered_subdomains, domain)
      @discovered = Array(discovered_subdomains).map(&:downcase).uniq
      @domain = domain.to_s.downcase
    end

    def generate
      candidates = Set.new
      extract_base_names.each do |base|
        PREFIXES.each do |prefix|
          candidates << "#{prefix}.#{@domain}"
          candidates << "#{prefix}-#{base}.#{@domain}"
          candidates << "#{base}-#{prefix}.#{@domain}"
        end

        SUFFIXES.each do |suffix|
          candidates << "#{base}#{suffix}.#{@domain}"
        end

        (2..5).each do |number|
          candidates << "#{base}#{number}.#{@domain}"
          candidates << "#{base}-#{number}.#{@domain}"
          candidates << "#{base}v#{number}.#{@domain}"
        end
      end

      PREFIXES.each { |prefix| candidates << "#{prefix}.#{@domain}" }
      (candidates - @discovered.to_set).to_a.sort
    end

    private

    def extract_base_names
      @discovered.filter_map do |subdomain|
        label = subdomain.delete_suffix(".#{@domain}")
        next if label == subdomain || label.empty?

        label.split(".").first
      end.uniq
    end
  end
end
