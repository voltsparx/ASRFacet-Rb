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

RSpec.describe ASRFacet::Scanner::Platform do
  it "returns Windows-specific labels when the host OS is Windows" do
    allow(RbConfig::CONFIG).to receive(:[]).with("host_os").and_return("mingw")

    expect(described_class.windows?).to be(true)
    expect(described_class.privilege_label).to eq("Run as Administrator")
  end

  it "returns macOS and Linux friendly requirement text" do
    allow(RbConfig::CONFIG).to receive(:[]).with("host_os").and_return("darwin")
    expect(described_class.raw_backend_requirements).to include("Nping")

    allow(RbConfig::CONFIG).to receive(:[]).with("host_os").and_return("linux")
    expect(described_class.raw_backend_requirements).to include("sudo")
  end
end
