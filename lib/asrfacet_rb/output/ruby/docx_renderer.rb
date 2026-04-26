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

begin
  require "caracal"
rescue LoadError
  Caracal = nil
end

require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class DocxRenderer < BaseRenderer
        def render(output_path)
          raise ASRFacet::Error, "Caracal is not installed" if Caracal.nil?

          Caracal::Document.save(output_path) do |doc|
            doc.h1 report_title
            doc.p "Generated: #{timestamp}"
            doc.p "Subdomains: #{@store.subdomains.size}"
            doc.p "IPs: #{@store.ips.size}"
            doc.p "Findings: #{@store.findings.size}"
            doc.hr
            @store.subdomains.each { |subdomain| doc.p subdomain }
          end
          log_success("DOCX", output_path)
        rescue ASRFacet::Error
          raise
        rescue StandardError => e
          raise ASRFacet::Error, "Caracal render failed: #{e.message}"
        end
      end
    end
  end
end
