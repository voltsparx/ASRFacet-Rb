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

RSpec.describe ASRFacet::Lab::TemplateServer do
  it "renders a local lab landing page with safe template descriptions" do
    html = described_class.new.send(:index_page)

    expect(html).to include("ASRFacet Local Validation Lab")
    expect(html).to include("/app")
    expect(html).to include("/browse/")
    expect(html).to include("safe placeholder surfaces")
  end
end
