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
require "tmpdir"

RSpec.describe ASRFacet::Output::JsonlStream do
  it "writes JSON lines to a target-specific file" do
    Dir.mktmpdir do |dir|
      stream = described_class.new("example.com", base_dir: dir)

      expect(stream.write("event", { ok: true, nested: { count: 1 } })).to eq(true)
      expect(File).to exist(stream.path)

      line = File.readlines(stream.path).last
      parsed = JSON.parse(line)

      expect(parsed["type"]).to eq("event")
      expect(parsed["payload"]).to eq({ "ok" => true, "nested" => { "count" => 1 } })
    end
  end
end
