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

RSpec.describe ASRFacet::Web::SessionStore do
  it "marks running sessions as interrupted after an unclean restart" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(name: "Recover me", config: { target: "example.com" })
      store.mark_running(session[:id], target: "example.com")
      path = File.join(dir, "#{session[:id]}.json")
      payload = JSON.parse(File.read(path))
      payload["last_heartbeat_at"] = (Time.now.utc - (described_class::HEARTBEAT_STALE_SECONDS + 5)).iso8601
      payload["run_meta"] ||= {}
      payload["run_meta"]["process_id"] = 999_999
      File.write(path, JSON.pretty_generate(payload))

      restarted = described_class.new(root: dir)
      recovered = restarted.fetch(session[:id])

      expect(recovered[:status]).to eq("interrupted")
      expect(recovered[:running]).to be(false)
      messages = Array(recovered[:events]).map do |event|
        if event.is_a?(Hash)
          event[:message] || event["message"]
        else
          event.to_s
        end
      end.join(" ")

      expect(messages).to include("unclean shutdown")
    end
  end

  it "does not interrupt a recently refreshed running session" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(name: "Live run", config: { target: "example.com" })
      store.mark_running(session[:id], target: "example.com", process_id: Process.pid)
      store.update_heartbeat(session[:id], process_id: Process.pid)

      restarted = described_class.new(root: dir)
      recovered = restarted.fetch(session[:id])

      expect(recovered[:status]).to eq("running")
      expect(recovered[:running]).to be(true)
    end
  end

  it "stores structured error details for failed sessions" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(name: "Failure details", config: { target: "example.com" })
      store.mark_failed(
        session[:id],
        summary: "The saved session could not finish cleanly.",
        details: "Passive runner: timeout while contacting a passive source.",
        recommendation: "Retry with lower pressure or when the source is reachable again."
      )

      recovered = store.fetch(session[:id])

      expect(recovered[:error]).to eq("The saved session could not finish cleanly.")
      expect(recovered[:error_details]).to include(
        summary: "The saved session could not finish cleanly.",
        recommendation: "Retry with lower pressure or when the source is reachable again."
      )
    end
  end

  it "preserves array and nil session fields when persisting to disk" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(name: "Shape check", config: { target: "example.com" })
      recovered = store.fetch(session[:id])

      expect(recovered[:events]).to eq([])
      expect(recovered[:error]).to be_nil
      expect(recovered[:last_heartbeat_at]).to be_nil
    end
  end

  it "normalizes web session config values for units, booleans, and scanner options" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(
        name: "Normalizer",
        config: {
          target: " example.com ",
          mode: "PORTSCAN",
          format: "PDF",
          ports: " 22,80,443 ",
          threads: "5000",
          timeout: "0",
          delay: "700000",
          monitor: "off",
          memory: "yes",
          headless: "true",
          verbose: "1",
          adaptive_rate: "0",
          webhook_platform: "teams",
          scan_type: "SYN",
          raw_backend: "NPING",
          scan_timing: "9",
          scan_version: "yes",
          scan_os: "true",
          scan_intensity: "-4",
          plugins: " exposure_score , attack_path ",
          filters: " scope_guard , duplicate_signal "
        }
      )

      recovered = store.fetch(session[:id])
      config = recovered[:config]

      expect(config).to include(
        target: "example.com",
        mode: "portscan",
        format: "pdf",
        ports: "22,80,443",
        threads: 1_000,
        timeout: 1,
        delay: 600_000,
        monitor: false,
        memory: true,
        headless: true,
        verbose: true,
        adaptive_rate: false,
        webhook_platform: "slack",
        scan_type: "syn",
        raw_backend: "nping",
        scan_timing: 5,
        scan_version: true,
        scan_os: true,
        scan_intensity: 0,
        plugins: "exposure_score,attack_path",
        filters: "scope_guard,duplicate_signal"
      )
    end
  end

  it "duplicates and deletes saved sessions cleanly" do
    Dir.mktmpdir do |dir|
      store = described_class.new(root: dir)
      session = store.create_or_update(name: "Baseline", config: { target: "example.com", mode: "portscan", raw_backend: "nping" })

      duplicated = store.duplicate(session[:id])

      expect(duplicated).not_to be_nil
      expect(duplicated[:id]).not_to eq(session[:id])
      expect(duplicated[:name]).to include("Baseline")
      expect(duplicated[:status]).to eq("idle")
      expect(duplicated.dig(:config, :raw_backend)).to eq("nping")
      expect(store.delete(session[:id])).to be(true)
      expect(store.fetch(session[:id])).to be_nil
    end
  end
end
