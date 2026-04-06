# Part of ASRFacet-Rb — authorized testing only
require "webmock/rspec"
require_relative "../lib/asrfacet_rb"

WebMock.disable_net_connect!(allow_localhost: true)

RSpec.configure do |config|
  config.disable_monkey_patching!
  config.expect_with :rspec do |expectations|
    expectations.syntax = :expect
  end
end
