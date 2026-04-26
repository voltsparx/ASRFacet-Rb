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
require "tmpdir"

RSpec.describe ASRFacet::UI::CLI do
  def capture_stdout
    original = $stdout
    buffer = StringIO.new
    $stdout = buffer
    yield
    buffer.string
  ensure
    $stdout = original
  end

  def wire_workspace_root(dir)
    manager = ASRFacet::Intelligence::SessionManager.new(root: dir)
    allow(ASRFacet::Intelligence::SessionManager).to receive(:new).and_return(manager)
    allow(ASRFacet::Intelligence::AssetGraph).to receive(:new).and_wrap_original do |method, target, **kwargs|
      method.call(target, **kwargs.merge(root: dir))
    end
    manager
  end

  it "lists, shows, exports, and deletes persisted workspaces through the CLI" do
    Dir.mktmpdir do |dir|
      manager = wire_workspace_root(dir)
      manager.create("lab.example.com")
      build_intelligence_graph(root: dir)

      list_output = capture_stdout { described_class.start(["workspace", "list"]) }
      show_output = capture_stdout { described_class.start(["workspace", "show", "lab.example.com"]) }
      export_output = capture_stdout { described_class.start(["workspace", "export", "lab.example.com", "--format", "csv"]) }

      expect(list_output).to include("lab.example.com")
      expect(JSON.parse(show_output)).to include("target" => "lab.example.com")

      export_path = export_output.strip
      expect(export_path).to end_with(".csv")
      expect(File).to exist(export_path)

      delete_output = capture_stdout { described_class.start(["workspace", "delete", "lab.example.com"]) }
      expect(delete_output).to include("Workspace deleted")
      expect(capture_stdout { described_class.start(["workspace", "show", "lab.example.com"]) }).to include("Workspace not found")
    end
  end

  it "tracks diffs, renders graph exports, and lists stored subdomains from a workspace" do
    Dir.mktmpdir do |dir|
      manager = wire_workspace_root(dir)
      manager.create("lab.example.com")
      build_intelligence_graph("intelligence_graph_previous", root: dir)
      manager.export("lab.example.com", format: "json")
      build_intelligence_graph(root: dir)

      track_output = capture_stdout { described_class.start(["track", "lab.example.com", "--since", "2099-01-01"]) }
      viz_output = capture_stdout { described_class.start(["viz", "lab.example.com", "--format", "mermaid"]) }
      subs_output = capture_stdout { described_class.start(["subs", "lab.example.com"]) }

      diff = JSON.parse(track_output)
      expect(diff.dig("summary", "added")).to be > 0
      expect(viz_output).to include("graph LR")
      expect(subs_output.lines.map(&:strip)).to eq(%w[api.lab.example.com app.lab.example.com])
    end
  end

  it "reports invalid track dates as parse errors without crashing" do
    Dir.mktmpdir do |dir|
      manager = wire_workspace_root(dir)
      manager.create("lab.example.com")
      build_intelligence_graph(root: dir)

      output = capture_stdout { described_class.start(["track", "lab.example.com", "--since", "not-a-date"]) }

      expect(output).to include("Invalid --since value")
    end
  end
end
