# Part of ASRFacet-Rb - authorized testing only
require "spec_helper"

RSpec.describe ASRFacet::Web::Server do
  it "renders the branded dashboard with theme toggles and framework icon" do
    html = described_class.new.send(:dashboard_html)

    expect(html).to include("/assets/icon")
    expect(html).to include("theme-light")
    expect(html).to include("theme-dark")
    expect(html).to include("theme-grey")
    expect(html).to include("ASRFacet-Rb")
  end
end
