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

module ASRFacet
  module Output
    module RuntimeDetector
      def self.node_available?
        @node_available ||= begin
          out = `node --version 2>&1`.strip
          $?.success? && out.match?(/\Av\d+\.\d+/)
        rescue Errno::ENOENT
          false
        end
      end

      def self.node_version
        return nil unless node_available?

        `node --version 2>&1`.strip
      end

      def self.npm_available?
        out = `npm --version 2>&1`.strip
        $?.success? && out.match?(/\A\d+\.\d+/)
      rescue Errno::ENOENT
        false
      end

      def self.js_dir
        File.expand_path("../js", __FILE__)
      end

      def self.js_installed?
        lock = File.join(js_dir, "package-lock.json")
        File.exist?(lock)
      end

      def self.engine_label
        if node_available?
          "Node.js #{node_version} - docx.js + react-pdf"
        else
          "Ruby fallback - Caracal + HexaPDF"
        end
      end
    end
  end
end
