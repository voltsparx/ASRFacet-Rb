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

RSpec.describe ASRFacet::KeyStore do
  it "stores, retrieves, lists, and deletes keys" do
    Dir.mktmpdir do |dir|
      stub_const("ASRFacet::KeyStore::KEY_FILE", File.join(dir, "keys.enc"))
      stub_const("ASRFacet::KeyStore::SALT_FILE", File.join(dir, "keys.salt"))
      store = described_class.new(passphrase: "spec-passphrase")

      store.set("shodan", "abc123")

      expect(store.get("shodan")).to eq("abc123")
      expect(store.list).to include("shodan")

      store.delete("shodan")

      expect(store.get("shodan")).to be_nil
    end
  end
end
