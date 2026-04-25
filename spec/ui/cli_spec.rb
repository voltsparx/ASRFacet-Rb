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
require "stringio"
require "tmpdir"

RSpec.describe ASRFacet::UI::CLI do
  describe "command aliases" do
    it "prints the version through the short alias" do
      expect { described_class.start(["v"]) }.to output("#{ASRFacet::VERSION}\n").to_stdout
    end

    it "prints the version through the long flag" do
      expect { described_class.start(["--version"]) }.to output("#{ASRFacet::VERSION}\n").to_stdout
    end

    it "routes help aliases to topic help" do
      expect { described_class.start(["h", "scan"]) }.to output(include("Explain: scan")).to_stdout
    end

    it "accepts the console flag shortcut and dispatches to console mode" do
      console = instance_double(ASRFacet::UI::Console, start: nil)
      allow(ASRFacet::UI::Console).to receive(:new).and_return(console)

      described_class.start(["-C"])

      expect(ASRFacet::UI::Console).to have_received(:new)
      expect(console).to have_received(:start)
    end

    it "accepts the web-session flag and dispatches to web mode" do
      server = instance_double(ASRFacet::Web::Server, start: nil)
      allow(ASRFacet::Web::Server).to receive(:new).and_return(server)

      described_class.start(["--web-session"])

      expect(ASRFacet::Web::Server).to have_received(:new)
      expect(server).to have_received(:start)
    end

    it "preserves web-session host and port flags" do
      server = instance_double(ASRFacet::Web::Server, start: nil)
      allow(ASRFacet::Web::Server).to receive(:new).and_return(server)

      described_class.start(["--web-session", "--web-host", "127.0.0.2", "--web-port", "4573"])

      expect(ASRFacet::Web::Server).to have_received(:new).with(host: "127.0.0.2", port: 4573)
      expect(server).to have_received(:start)
    end

    it "supports the about flag shortcut" do
      expect { described_class.start(["--about"]) }.to output(include("ASRFacet-Rb", "authorized attack surface reconnaissance")).to_stdout
    end

    it "supports the explain flag shortcut" do
      expect { described_class.start(["--explain", "scope"]) }.to output(include("Explain: scope")).to_stdout
    end

    it "shows the new adaptive and headless flags in the help output" do
      expect { described_class.start(["help"]) }.to output(include("--headless", "--webhook-url", "--delay", "--adaptive-rate", "--web-session", "--about", "--explain", "lab")).to_stdout
    end

    it "stores a full report bundle for scans" do
      Dir.mktmpdir do |dir|
        store = ASRFacet::ResultStore.new
        store.add(:subdomains, "example.com")
        store.add(:open_ports, { host: "example.com", port: 443, service: "https", banner: "nginx" })

        result = {
          store: store,
          top_assets: [{ host: "example.com", total_score: 80, matched_rules: ["https"] }],
          diff: {},
          change_summary: "",
          js_endpoints: { js_files_scanned: 1, endpoints_found: ["/api/v1/users"], potential_secrets: 0, findings: [] },
          correlations: [],
          probabilistic_subdomains: [],
          stream_path: File.join(dir, "streams", "example_com.jsonl"),
          summary: { subdomains: 1, open_ports: 1 }
        }

        pipeline = instance_double(ASRFacet::Pipeline, run: result)
        allow(ASRFacet::Pipeline).to receive(:new).and_return(pipeline)
        allow(ASRFacet::Config).to receive(:fetch).and_call_original
        allow(ASRFacet::Config).to receive(:fetch).with("output", "directory").and_return(dir)

        output = capture_stdout { described_class.start(["scan", "example.com"]) }

        expect(output).to include("Stored reports in")
        expect(Dir.glob(File.join(dir, "reports", "example_com", "*", "report.html"))).not_to be_empty
        expect(Dir.glob(File.join(dir, "reports", "example_com", "*", "report.json"))).not_to be_empty
        expect(Dir.glob(File.join(dir, "reports", "example_com", "*", "report.txt"))).not_to be_empty
        expect(Dir.glob(File.join(dir, "reports", "example_com", "*", "report.cli.txt"))).not_to be_empty
      end
    end

    it "prints fault-isolation and integrity notes from scan results" do
      store = ASRFacet::ResultStore.new
      store.add(:subdomains, "example.com")
      result = {
        store: store,
        top_assets: [],
        summary: { subdomains: 1 },
        execution: {
          failures: [
            {
              engine: "http_engine",
              summary: "Http Engine hit a recoverable problem and ASRFacet-Rb continued with fault isolation.",
              details: "example.com: timeout",
              recommendation: "Increase --timeout, reduce --threads, or retry against a more responsive target window."
            }
          ],
          integrity: {
            status: "warning",
            summary: "ASRFacet-Rb found non-blocking integrity issues. The framework can still run, but some surfaces may be incomplete.",
            issues: [
              {
                severity: "warning",
                summary: "An optional framework file is missing.",
                details: "README.md was not found. Core scanning can continue, but a support surface may be incomplete.",
                recommendation: "Refresh the install if you expect the optional documentation or man page to be present."
              }
            ]
          }
        }
      }
      pipeline = instance_double(ASRFacet::Pipeline, run: result)
      allow(ASRFacet::Pipeline).to receive(:new).and_return(pipeline)
      allow(ASRFacet::Core::IntegrityChecker).to receive(:check).and_return(status: "ok", summary: "ok", issues: [], recommendations: [])

      output = capture_stdout { described_class.start(["scan", "example.com"]) }

      expect(output).to include("Fault Isolation and Execution Notes")
      expect(output).to include("Framework Integrity")
    end

    it "blocks scan execution when framework integrity is critically broken" do
      allow(ASRFacet::Pipeline).to receive(:new)
      allow(ASRFacet::Core::IntegrityChecker).to receive(:check).and_return(
        status: "critical",
        summary: "ASRFacet-Rb found blocking integrity problems and should be repaired before active use.",
        issues: [
          {
            summary: "A required framework file is missing.",
            details: "wordlists/subdomains_small.txt could not be found under the application root.",
            path: "wordlists/subdomains_small.txt",
            recommendation: "Repair or reinstall the framework so the missing runtime file is restored."
          }
        ],
        recommendations: ["Repair or reinstall the framework so the missing runtime file is restored."]
      )

      output = capture_stdout { described_class.start(["scan", "example.com"]) }

      expect(output).to include("Framework integrity check failed")
      expect(output).to include("A required framework file is missing")
      expect(ASRFacet::Pipeline).not_to have_received(:new)
    end
  end

  def capture_stdout
    original = $stdout
    buffer = StringIO.new
    $stdout = buffer
    yield
    buffer.string
  ensure
    $stdout = original
  end
end
