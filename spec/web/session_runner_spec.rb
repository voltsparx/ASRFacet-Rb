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

RSpec.describe ASRFacet::Web::SessionRunner do
  let(:integrity_ok) { { status: "ok", summary: "ASRFacet-Rb integrity checks passed.", issues: [], recommendations: [] } }

  before do
    allow(ASRFacet::Core::IntegrityChecker).to receive(:check).and_return(integrity_ok)
    allow(ASRFacet::Core::IntegrityChecker).to receive(:critical?).and_return(false)
  end

  it "runs portscan sessions through the scanner engine and saves requested report artifacts" do
    Dir.mktmpdir do |dir|
      output_root = File.join(dir, "output")
      store = ASRFacet::Web::SessionStore.new(root: File.join(dir, "sessions"))
      session = store.create_or_update(
        name: "Scanner session",
        config: {
          target: "example.com",
          mode: "portscan",
          format: "all",
          ports: "22,80",
          scan_type: "syn",
          scan_timing: 4,
          scan_version: true,
          scan_os: true,
          scan_intensity: 9,
          verbose: true
        }
      )

      scan_engine = instance_double(ASRFacet::Scanner::ScanEngine, scan: :scan_result)
      router = instance_double(ASRFacet::Output::OutputRouter)
      sarif_formatter = instance_double(ASRFacet::Output::SarifFormatter)
      payload_store = ASRFacet::ResultStore.new
      payload_store.add(:subdomains, "example.com")
      payload_store.add(:open_ports, { host: "example.com", port: 443, service: "https" })

      allow(ASRFacet::Config).to receive(:fetch).and_call_original
      allow(ASRFacet::Config).to receive(:fetch).with("output", "directory").and_return(output_root)
      allow(ASRFacet::Scanner::ScanEngine).to receive(:new).with(
        hash_including(
          scan_type: "syn",
          timing: 4,
          verbosity: 1,
          version_detection: true,
          os_detection: true,
          version_intensity: 9,
          ports: "22,80"
        )
      ).and_return(scan_engine)
      allow(ASRFacet::Scanner::ResultAdapter).to receive(:to_payload).with(:scan_result, target: "example.com").and_return(
        {
          store: payload_store,
          top_assets: [],
          summary: payload_store.summary
        }
      )
      allow(ASRFacet::Output::OutputRouter).to receive(:new).and_return(router)
      allow(ASRFacet::Output::SarifFormatter).to receive(:new).and_return(sarif_formatter)
      allow(router).to receive(:render) do |_format, path|
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, "artifact")
      end
      allow(sarif_formatter).to receive(:save) do |_payload, path|
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, "{}")
        path
      end

      described_class.new(session_store: store).send(:run_session, session[:id])
      completed = store.fetch(session[:id])

      expect(completed[:status]).to eq("completed")
      expect(completed.dig(:summary, :open_ports)).to eq(1)
      expect(completed.dig(:artifacts, :cli_report)).to end_with("report.cli.txt")
      expect(completed.dig(:artifacts, :pdf_report)).to end_with("report.pdf")
      expect(completed.dig(:artifacts, :docx_report)).to end_with("report.docx")
      expect(completed.dig(:artifacts, :sarif_report)).to end_with("report.sarif")
      expect(completed.dig(:artifacts, :csv_ports_report)).to end_with("report_ports.csv")
      expect(File).to exist(completed.dig(:artifacts, :pdf_report))
      expect(File).to exist(completed.dig(:artifacts, :docx_report))
      expect(File).to exist(completed.dig(:artifacts, :sarif_report))
      expect(ASRFacet::Output::OutputRouter).to have_received(:new)
    end
  end

  it "routes ports-only web sessions through the scanner engine connect scan" do
    Dir.mktmpdir do |dir|
      output_root = File.join(dir, "output")
      store = ASRFacet::Web::SessionStore.new(root: File.join(dir, "sessions"))
      session = store.create_or_update(
        name: "Ports session",
        config: {
          target: "192.0.2.10",
          mode: "ports",
          format: "cli",
          ports: "80,443"
        }
      )

      scan_engine = instance_double(ASRFacet::Scanner::ScanEngine, scan: :scan_result)
      payload_store = ASRFacet::ResultStore.new

      allow(ASRFacet::Config).to receive(:fetch).and_call_original
      allow(ASRFacet::Config).to receive(:fetch).with("output", "directory").and_return(output_root)
      allow(ASRFacet::Scanner::ScanEngine).to receive(:new).with(
        hash_including(
          scan_type: "connect",
          ports: "80,443",
          version_detection: false,
          os_detection: false
        )
      ).and_return(scan_engine)
      allow(ASRFacet::Scanner::ResultAdapter).to receive(:to_payload).and_return(
        {
          store: payload_store,
          top_assets: [],
          summary: payload_store.summary
        }
      )

      described_class.new(session_store: store).send(:run_session, session[:id])

      expect(ASRFacet::Scanner::ScanEngine).to have_received(:new).with(
        hash_including(scan_type: "connect", ports: "80,443")
      )
      expect(store.fetch(session[:id])[:status]).to eq("completed")
    end
  end
end
