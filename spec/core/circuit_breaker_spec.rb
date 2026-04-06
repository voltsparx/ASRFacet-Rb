# Part of ASRFacet-Rb — authorized testing only
require "spec_helper"

RSpec.describe ASRFacet::Core::CircuitBreaker do
  it "opens after reaching the failure threshold" do
    breaker = described_class.new(threshold: 2, cooldown: 60)

    breaker.record_failure
    expect(breaker.allow?).to eq(true)

    breaker.record_failure

    expect(breaker.open?).to eq(true)
    expect(breaker.allow?).to eq(false)
  end

  it "closes again after a success" do
    breaker = described_class.new(threshold: 1, cooldown: 60)

    breaker.record_failure
    expect(breaker.open?).to eq(true)

    breaker.record_success

    expect(breaker.open?).to eq(false)
    expect(breaker.allow?).to eq(true)
  end
end
