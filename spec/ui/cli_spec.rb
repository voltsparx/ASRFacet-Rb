# Part of ASRFacet-Rb - authorized testing only
require "spec_helper"
require "stringio"
require "tmpdir"

RSpec.describe ASRFacet::UI::CLI do
  describe "command aliases" do
    it "prints the version through the short alias" do
      expect { described_class.start(["v"]) }.to output("0.1.0\n").to_stdout
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

    it "shows the new adaptive and headless flags in the help output" do
      expect { described_class.start(["help"]) }.to output(include("--headless", "--webhook-url", "--delay", "--adaptive-rate", "--web-session")).to_stdout
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
