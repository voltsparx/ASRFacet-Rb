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

RSpec.describe ASRFacet::UI::Manual do
  it "documents the direct portscan command in the commands section" do
    commands = described_class.plain_text("commands")

    expect(commands).to include("portscan TARGET")
    expect(commands).to include("scanner engine directly")
  end

  it "documents the expanded output formats" do
    outputs = described_class.plain_text("outputs")

    expect(outputs).to include("pdf")
    expect(outputs).to include("docx")
    expect(outputs).to include("sarif")
    expect(outputs).to include("CSV")
  end

  it "renders the full manual when no section is requested" do
    manual = described_class.plain_text

    expect(manual).to include("COMMANDS")
    expect(manual).to include("OUTPUTS")
    expect(manual).to include("SAFETY")
  end
end
