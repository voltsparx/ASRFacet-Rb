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

RSpec.describe ASRFacet::Engines::PortEngine do
  let(:engine) { described_class.new }

  it "identifies an open port on localhost" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]

    expect(engine.scan_port("127.0.0.1", port, timeout: 1)).to eq(:open)
  ensure
    server&.close
  end

  it "identifies a closed port on localhost" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close

    expect(engine.scan_port("127.0.0.1", port, timeout: 1)).to eq(:closed)
  end

  it "returns filtered when the socket never becomes writable" do
    fake_socket = instance_double(Socket)
    allow(Socket).to receive(:new).and_return(fake_socket)
    allow(Socket).to receive(:sockaddr_in).and_return("sockaddr")
    allow(fake_socket).to receive(:connect_nonblock).and_raise(Errno::EINPROGRESS)
    allow(fake_socket).to receive(:getsockopt)
    allow(fake_socket).to receive(:close)
    allow(IO).to receive(:select).and_return(nil)

    expect(engine.scan_port("127.0.0.1", 81, timeout: 1)).to eq(:filtered)
  end
end
