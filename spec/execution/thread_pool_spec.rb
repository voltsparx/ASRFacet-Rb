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

RSpec.describe ASRFacet::Execution::ThreadPool do
  it "tracks completions, failures, and timeouts without crashing the pool" do
    pool = described_class.new(workers: 2, default_timeout: 0.05)
    results = Queue.new

    pool.enqueue(label: "ok-job") { results << :ok }
    pool.enqueue(label: "boom-job") { raise "boom" }
    pool.enqueue(timeout: 0.02, label: "slow-job") { sleep 0.1 }
    pool.wait

    expect(results.pop).to eq(:ok)
    expect(pool.completed).to eq(1)
    expect(pool.failed).to eq(2)
    expect(pool.timed_out).to eq(1)
    expect(pool.errors).to include(include(label: "boom-job", message: "boom"))
    expect(pool.errors).to include(include(label: "slow-job", type: "job_timeout"))
  end

  it "supports compatibility resizing" do
    pool = described_class.new(workers: 1)

    expect(pool.current_size).to be >= 1
    expect(pool.resize(3)).to eq(3)
    expect(pool.current_size).to be >= 1

    pool.wait
  end
end
