# Part of ASRFacet-Rb — authorized testing only
require "spec_helper"

RSpec.describe ASRFacet::Engines::HttpEngine do
  let(:engine) { described_class.new }

  before do
    stub_request(:get, "https://example.com").to_return(
      status: 200,
      body: <<~HTML,
        <html>
          <head><title>Example App</title></head>
          <body>
            <script src="/assets/react.js"></script>
            <!-- hello -->
          </body>
        </html>
      HTML
      headers: {
        "Server" => "nginx",
        "Set-Cookie" => "laravel_session=test"
      }
    )

    stub_request(:get, %r{\Ahttps://example\.com/}).to_return(status: 404, body: "Not Found")
    stub_request(:get, "https://example.com/.git/HEAD").to_return(status: 200, body: "ref: refs/heads/main")
    stub_request(:get, "https://example.com/admin").to_return(status: 302, body: "")
  end

  it "detects technologies and missing security headers" do
    result = engine.probe("example.com")

    expect(result[:title]).to eq("Example App")
    expect(result[:technologies]).to include("Nginx", "Laravel", "React")
    expect(result[:security_headers]["Strict-Transport-Security"]).to be_nil
  end

  it "records interesting non-404 paths" do
    result = engine.probe("example.com")
    paths = result[:interesting_paths].map { |entry| entry[:path] }

    expect(paths).to include("/.git/HEAD", "/admin")
  end
end
