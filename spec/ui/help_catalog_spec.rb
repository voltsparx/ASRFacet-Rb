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

RSpec.describe ASRFacet::UI::HelpCatalog do
  it "explains the direct portscan surface" do
    text = described_class.explain("portscan")

    expect(text).to include("Run the full scanner engine directly")
    expect(text).to include("connect|syn|udp|ack|fin|null|xmas|window|maimon|ping|service")
    expect(text).to include("--timing 0-5")
  end

  it "includes expanded report formats in the help menu" do
    menu = described_class.menu

    expect(menu).to include("portscan TARGET")
    expect(menu).to include("cli, json, html, txt, csv, pdf, docx, all, or sarif")
  end

  it "normalizes aliases to the new topic names" do
    expect(described_class.normalize("web")).to eq("web-session")
    expect(described_class.normalize("config")).to eq("configuration")
    expect(described_class.normalize("--format")).to eq("format")
  end
end
