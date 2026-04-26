# frozen_string_literal: true
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

RSpec.describe ASRFacet::Intelligence::Dns::DnsPermutator do
  it "generates word, number, prefix, suffix, and fuzzy mutations" do
    Dir.mktmpdir do |dir|
      wordlist = File.join(dir, "alts.txt")
      File.write(wordlist, "admin\nbeta\n")
      permutator = described_class.new(wordlist_path: wordlist, edit_distance: 1)

      results = permutator.generate(["dev-api.example.com", "app1.example.com"], "example.com")

      expect(results).to include("admin-api.example.com")
      expect(results).to include("app0.example.com")
      expect(results).to include("beta-app1.example.com")
      expect(results.any? { |entry| entry.end_with?(".example.com") }).to be(true)
    end
  end

  it "returns an empty array when there are no discovered subdomains" do
    permutator = described_class.new(alteration_words: %w[admin beta])

    expect(permutator.generate([], "example.com")).to eq([])
  end

  it "does not include the original names or apex domain in output" do
    permutator = described_class.new(alteration_words: %w[admin beta])
    results = permutator.generate(["app.example.com"], "example.com")

    expect(results).not_to include("app.example.com", "example.com")
  end
end
