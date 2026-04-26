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

RSpec.describe ASRFacet::Output::OutputRouter do
  subject(:router) { described_class.new(build_output_store, output_fixture_data[:target], asset_graph: build_output_graph) }

  it "routes PDF and DOCX rendering through the JavaScript bridges when Node.js is available" do
    pdf_renderer = instance_double(ASRFacet::Output::Js::JsPdfBridge, render: true)
    docx_renderer = instance_double(ASRFacet::Output::Js::JsDocxBridge, render: true)

    allow(ASRFacet::Output::RuntimeDetector).to receive(:node_available?).and_return(true)
    allow(ASRFacet::Output::Js::JsPdfBridge).to receive(:new).and_return(pdf_renderer)
    allow(ASRFacet::Output::Js::JsDocxBridge).to receive(:new).and_return(docx_renderer)

    router.render("pdf", File.join(Dir.tmpdir, "fixture.pdf"))
    router.render("docx", File.join(Dir.tmpdir, "fixture.docx"))

    expect(ASRFacet::Output::Js::JsPdfBridge).to have_received(:new)
    expect(ASRFacet::Output::Js::JsDocxBridge).to have_received(:new)
    expect(pdf_renderer).to have_received(:render)
    expect(docx_renderer).to have_received(:render)
  end

  it "falls back to the Ruby PDF and DOCX renderers when Node.js is unavailable" do
    pdf_renderer = instance_double(ASRFacet::Output::Ruby::PdfRenderer, render: true)
    docx_renderer = instance_double(ASRFacet::Output::Ruby::DocxRenderer, render: true)

    allow(ASRFacet::Output::RuntimeDetector).to receive(:node_available?).and_return(false)
    allow(ASRFacet::Output::Ruby::PdfRenderer).to receive(:new).and_return(pdf_renderer)
    allow(ASRFacet::Output::Ruby::DocxRenderer).to receive(:new).and_return(docx_renderer)

    router.render("pdf", File.join(Dir.tmpdir, "fixture.pdf"))
    router.render("docx", File.join(Dir.tmpdir, "fixture.docx"))

    expect(ASRFacet::Output::Ruby::PdfRenderer).to have_received(:new)
    expect(ASRFacet::Output::Ruby::DocxRenderer).to have_received(:new)
    expect(pdf_renderer).to have_received(:render)
    expect(docx_renderer).to have_received(:render)
  end

  it "continues rendering later formats during render_all when one renderer raises an ASRFacet error" do
    formats = []

    allow(router).to receive(:render).and_wrap_original do |_method, format, path|
      formats << [format, path]
      raise ASRFacet::Error, "PDF unavailable" if format == "pdf"

      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, format)
    end

    Dir.mktmpdir do |dir|
      expect { router.render_all(dir) }.not_to raise_error
    end

    expect(formats.map(&:first)).to eq(%w[txt html json csv pdf docx])
  end
end
