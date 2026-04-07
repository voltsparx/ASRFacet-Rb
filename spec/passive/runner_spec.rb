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

RSpec.describe ASRFacet::Passive::Runner do
  let(:success_source) do
    klass = Class.new(ASRFacet::Passive::BaseSource) do
      def name
        "success_source"
      end

      def run(_domain, _api_keys = {})
        ["api.example.com", "dev.example.com"]
      end
    end
    stub_const("PassiveRunnerSuccessSource", klass)
  end

  let(:duplicate_source) do
    klass = Class.new(ASRFacet::Passive::BaseSource) do
      def name
        "duplicate_source"
      end

      def run(_domain, _api_keys = {})
        ["dev.example.com", "www.example.com"]
      end
    end
    stub_const("PassiveRunnerDuplicateSource", klass)
  end

  let(:failing_source) do
    klass = Class.new(ASRFacet::Passive::BaseSource) do
      def name
        "failing_source"
      end

      def run(_domain, _api_keys = {})
        raise StandardError, "source failed"
      end
    end
    stub_const("PassiveRunnerFailingSource", klass)
  end

  it "aggregates unique subdomains and captures per-source errors" do
    stub_const("#{described_class}::SOURCES", [success_source, duplicate_source, failing_source])

    result = described_class.new("example.com").run

    expect(result[:subdomains]).to eq(%w[api.example.com dev.example.com www.example.com])
    expect(result[:errors].length).to eq(1)
    expect(result[:errors].first).to include(failing_source.name.split("::").last)
    expect(result[:source_count]).to eq(3)
  end
end
