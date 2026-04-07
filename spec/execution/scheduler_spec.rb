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

RSpec.describe ASRFacet::Execution::Scheduler do
  it "records successful and failed stages" do
    scheduler = described_class.new

    success = scheduler.stage("demo") { "done" }
    failure = scheduler.stage("broken") { raise "fail" }

    expect(success[:status]).to eq(:success)
    expect(success[:result]).to eq("done")
    expect(failure[:status]).to eq(:failed)
    expect(failure[:error]).to eq("fail")
    expect(scheduler.history.size).to eq(2)
  end

  it "retries transient failures with backoff" do
    scheduler = described_class.new
    attempts = 0

    result = scheduler.with_retry(max_retries: 2, base_delay: 0) do
      attempts += 1
      raise "retry me" if attempts < 3

      :ok
    end

    expect(result).to eq(:ok)
    expect(attempts).to eq(3)
  end

  it "runs scheduled collections with isolated task errors" do
    scheduler = described_class.new
    result = scheduler.schedule([1, 2, 3], workers: 2, timeout: 0.05, label: "demo") do |item|
      raise "bad" if item == 2

      item * 2
    end

    expect(result[:results]).to contain_exactly(2, 6)
    expect(result[:errors]).to include(include(label: "demo-1", message: "bad"))
  end
end
