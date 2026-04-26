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
  require "hexapdf"
rescue LoadError
  HexaPDF = nil
end

require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class PdfRenderer < BaseRenderer
        def render(output_path)
          raise ASRFacet::Error, "HexaPDF is not installed" if HexaPDF.nil?

          document = HexaPDF::Document.new
          page = document.pages.add
          canvas = page.canvas
          canvas.font("Helvetica", size: 18)
          canvas.text(report_title, at: [48, 760])
          canvas.font("Helvetica", size: 10)
          canvas.text("Generated: #{timestamp}", at: [48, 740])
          canvas.text("Subdomains: #{@store.subdomains.size}", at: [48, 720])
          canvas.text("IPs: #{@store.ips.size}", at: [48, 705])
          canvas.text("Findings: #{@store.findings.size}", at: [48, 690])
          document.write(output_path, optimize: true)
          log_success("PDF", output_path)
        rescue ASRFacet::Error
          raise
        rescue StandardError => e
          raise ASRFacet::Error, "HexaPDF render failed: #{e.message}"
        end
      end
    end
  end
end
