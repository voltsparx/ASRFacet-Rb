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

RSpec.describe ASRFacet::Scanner::Privilege do
  it "classifies fin, null, xmas, and other raw modes as raw scan types" do
    expect(described_class.raw_scan_type?(:fin)).to be(true)
    expect(described_class.raw_scan_type?(:null)).to be(true)
    expect(described_class.raw_scan_type?(:xmas)).to be(true)
    expect(described_class.raw_scan_type?(:connect)).to be(false)
  end

  it "raises a clear error when a raw-capable backend is missing" do
    tcp_prober = instance_double(ASRFacet::Scanner::Probes::TCPProber, raw_socket_capable?: false)

    expect do
      described_class.validate!(scan_type: :fin, tcp_prober: tcp_prober)
    end.to raise_error(ASRFacet::ScanError, /raw-capable TCP prober/i)
  end
end
