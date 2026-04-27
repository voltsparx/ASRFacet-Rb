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

RSpec.describe ASRFacet::Scanner::RedTeamHintEngine do
  it "returns structured hint objects" do
    hints = described_class.hints_for(service: "ssh", version: "OpenSSH_7.7", port: 22, cpe: "cpe:/a:openbsd:openssh:7.7")

    expect(hints).to all(be_a(ASRFacet::Scanner::Results::PortResult::RedTeamHint))
  end

  it "returns the vsftpd 2.3.4 backdoor hint" do
    hints = described_class.hints_for(service: "ftp", version: "2.3.4", port: 21, cpe: "cpe:/a:vsftpd:vsftpd:2.3.4")

    expect(hints.map(&:cve)).to include("CVE-2011-2523")
  end

  it "returns a generic hint instead of raising for unknown services" do
    hints = described_class.hints_for(service: "mystery", version: nil, port: 12345, cpe: nil)

    expect(hints).not_to be_empty
    expect(hints.first.operator_action).not_to be_empty
  end

  it "ensures every hint has an operator action" do
    hints = described_class.hints_for(service: "mysql", version: "5.7.28", port: 3306, cpe: "cpe:/a:mysql:mysql:5.7.28")

    expect(hints).to all(satisfy { |hint| !hint.operator_action.to_s.empty? })
  end
end
