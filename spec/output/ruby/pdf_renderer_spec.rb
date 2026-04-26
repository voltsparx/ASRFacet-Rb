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

require "spec_helper"
require "tmpdir"
require "asrfacet_rb/output/ruby/pdf_renderer"

RSpec.describe ASRFacet::Output::Ruby::PdfRenderer do
  let(:store) do
    ASRFacet::ResultStore.new.tap do |result|
      result.add_subdomain("portal.example.com")
      result.add_ip("1.2.3.4")
    end
  end

  it "renders a pdf when HexaPDF is available" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.pdf")
      renderer = described_class.new(store, "example.com", charts: {})

      if defined?(HexaPDF) && !HexaPDF.nil?
        renderer.render(path)
        expect(File.exist?(path)).to be(true)
      else
        expect { renderer.render(path) }.to raise_error(ASRFacet::Error, /HexaPDF is not installed/)
      end
    end
  end
end
