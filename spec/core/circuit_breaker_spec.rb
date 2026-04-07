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

RSpec.describe ASRFacet::Core::CircuitBreaker do
  it "opens after reaching the failure threshold" do
    breaker = described_class.new("test-breaker", failure_threshold: 2, cooldown_seconds: 60)

    breaker.record_failure
    expect(breaker.allow?).to eq(true)

    breaker.record_failure

    expect(breaker.open?).to eq(true)
    expect(breaker.allow?).to eq(false)
  end

  it "transitions to half-open after cooldown and closes after enough successes" do
    breaker = described_class.new("test-breaker", failure_threshold: 1, cooldown_seconds: 1, success_threshold: 2)

    breaker.record_failure
    expect(breaker.open?).to eq(true)

    breaker.instance_variable_set(:@opened_at, Time.now - 2)
    expect(breaker.allow?).to eq(true)
    expect(breaker.half_open?).to eq(true)

    breaker.record_success
    expect(breaker.half_open?).to eq(true)

    breaker.record_success

    expect(breaker.closed?).to eq(true)
    expect(breaker.allow?).to eq(true)
  end

  it "raises CircuitOpenError when call executes while the circuit is open" do
    breaker = described_class.new("test-breaker", failure_threshold: 1, cooldown_seconds: 60)
    breaker.record_failure

    expect { breaker.call { true } }.to raise_error(ASRFacet::Core::CircuitBreaker::CircuitOpenError)
  end
end
