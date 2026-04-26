# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
require "stringio"

RSpec.describe ASRFacet::Scanner::VerboseLogger do
  it "prints a port table in the expected column format" do
    stream = StringIO.new
    logger = described_class.new(level: 0, stream: stream)
    host = ASRFacet::Scanner::Results::HostResult.new(host: "example.com", up: true)
    host.add_port(ASRFacet::Scanner::Results::PortResult.new(port: 22, proto: :tcp, state: :open, service: "ssh", version: "OpenSSH 8.2p1"))

    logger.print_port_table(host)

    expect(stream.string).to include("PORT      STATE   SERVICE    VERSION")
    expect(stream.string).to include("22/tcp     open     ssh        OpenSSH 8.2p1")
  end

  it "suppresses probe chatter below level 3" do
    stream = StringIO.new
    logger = described_class.new(level: 2, stream: stream)

    logger.probe_sent("example.com", 80, "HTTPOptions")

    expect(stream.string).to eq("")
  end

  it "prints probe chatter at level 3" do
    stream = StringIO.new
    logger = described_class.new(level: 3, stream: stream)

    logger.probe_received("example.com", 80, 128)

    expect(stream.string).to include("probe received 128 bytes")
  end
end
