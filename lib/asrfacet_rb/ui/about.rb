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

module ASRFacet
  module UI
    module About
      module_function

      def plain_text
        [
          "ASRFacet-Rb",
          "Version: #{ASRFacet::VERSION}",
          "",
          "ASRFacet-Rb is a Ruby 3.2+ authorized attack surface reconnaissance framework built for infrastructure inventory, security posture validation, and repeatable external visibility mapping.",
          "",
          "Primary capabilities:",
          "  - Passive source aggregation",
          "  - Recursive DNS and certificate enrichment",
          "  - Threaded port and service discovery",
          "  - HTTP fingerprinting, crawling, and JavaScript endpoint mining",
          "  - Correlation, scoring, recon memory, and change tracking",
          "  - CLI, console, offline reports, and a local web session UI",
          "",
          "Operator surfaces:",
          "  - CLI for one-shot runs",
          "  - Console for guided and repeat operator workflows",
          "  - Web session mode for local saved sessions, live activity, and report browsing",
          "  - Built-in docs, explain topics, and manual pages for self-guided learning",
          "",
          "Safety model:",
          "  - Use only on systems you own or have explicit written permission to test.",
          "  - Scope and exclusion controls exist to help prevent accidental out-of-scope validation.",
          "  - Resilience features favor stable, repeatable runs over brittle high-speed behavior.",
          "",
          "Testing support:",
          "  - A local lab mode provides pre-built template pages so you can validate ASRFacet-Rb against safe local targets before using it on real authorized environments.",
          "",
          "Project paths:",
          "  - Output: ~/.asrfacet_rb/output/",
          "  - Web sessions: ~/.asrfacet_rb/web_sessions/",
          "  - Recon memory: ~/.asrfacet_rb/memory/",
          "",
          "Repository:",
          "  #{ASRFacet::Metadata::REPO_URL}",
          "Author:",
          "  #{ASRFacet::Metadata::AUTHOR} <#{ASRFacet::Metadata::EMAIL}>"
        ].join("\n")
      rescue StandardError
        "ASRFacet-Rb"
      end

      def summary_lines
        [
          "Version #{ASRFacet::VERSION}.",
          "Authorized attack surface reconnaissance for Ruby 3.2+.",
          "Designed for inventory, mapping, validation, and repeatable reporting.",
          "Ships with CLI, console, web-session UI, offline reports, and a safe local lab."
        ]
      rescue StandardError
        []
      end
    end
  end
end
