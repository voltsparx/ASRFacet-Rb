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

RSpec.describe ASRFacet::Web::Server do
  it "renders the branded dashboard shell with external assets and workspace views" do
    html = described_class.new.send(:dashboard_html)

    expect(html).to include("/assets/icon")
    expect(html).to include("/assets/dashboard.css")
    expect(html).to include("/assets/dashboard.js")
    expect(html).to include("ASRFacet-Rb")
    expect(html).to include("Session Builder")
    expect(html).to include("Activity Drawer")
    expect(html).to include("About ASRFacet-Rb")
    expect(html).to include("Documentation")
  end
end
