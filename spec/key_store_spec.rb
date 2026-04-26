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
  def build_store(dir, passphrase: "spec-passphrase")
    described_class.new(
      passphrase: passphrase,
      key_file: File.join(dir, "keys.enc"),
      salt_file: File.join(dir, "keys.salt")
    )
  end

  it "stores, retrieves, lists, and deletes keys" do
    Dir.mktmpdir do |dir|
      store = build_store(dir)

      store.set("shodan", "abc123")
      store.set("virustotal", "def456")

      expect(store.get("shodan")).to eq("abc123")
      expect(store.list).to eq(%w[shodan virustotal])
      expect(store.all).to eq("shodan" => "abc123", "virustotal" => "def456")

      store.delete("shodan")

      expect(store.get("shodan")).to be_nil
      expect(store.list).to eq(["virustotal"])
    end
  end

  it "raises a key store error when the encrypted payload cannot be decrypted" do
    Dir.mktmpdir do |dir|
      good_store = build_store(dir, passphrase: "good-passphrase")
      good_store.set("urlscan", "token-1")

      bad_store = build_store(dir, passphrase: "wrong-passphrase")

      expect { bad_store.get("urlscan") }.to raise_error(ASRFacet::KeyStoreError, /Failed to decrypt key store/)
    end
  end

  it "returns empty collections when the store has not been created yet" do
    Dir.mktmpdir do |dir|
      store = build_store(dir)

      expect(store.get("missing")).to be_nil
      expect(store.list).to eq([])
      expect(store.all).to eq({})

      expect { store.delete("missing") }.not_to raise_error
    end
  end
end
