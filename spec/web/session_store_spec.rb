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
end
