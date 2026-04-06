# Part of ASRFacet-Rb — authorized testing only
require "spec_helper"

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

    it "shows the new adaptive and headless flags in the help output" do
      expect { described_class.start(["help"]) }.to output(include("--headless", "--webhook-url", "--delay", "--adaptive-rate")).to_stdout
    end
  end
end
