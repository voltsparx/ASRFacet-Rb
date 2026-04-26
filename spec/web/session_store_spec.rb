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
end
