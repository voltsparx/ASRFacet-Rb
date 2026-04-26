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

require "open3"

module ASRFacet
  module Output
    module RuntimeDetector
      module_function

      def node_available?
        !node_version.nil?
      end

      def node_version
        stdout, status = capture("node", "--version")
        return nil unless status&.success?

        version = stdout.to_s.strip
        version.match?(/\Av\d+\.\d+\.\d+/) ? version : nil
      rescue Errno::ENOENT, IOError, SystemCallError
        nil
      end

      def npm_available?
        stdout, status = capture("npm", "--version")
        return false unless status&.success?

        stdout.to_s.strip.match?(/\A\d+\.\d+\.\d+/)
      rescue Errno::ENOENT, IOError, SystemCallError
        false
      end

      def js_dir
        File.expand_path("js", __dir__)
      end

      def js_installed?
        return false unless File.directory?(js_dir)

        package_manifest = File.join(js_dir, "package.json")
        node_modules = File.join(js_dir, "node_modules")
        package_lock = File.join(js_dir, "package-lock.json")

        File.file?(package_manifest) && (File.directory?(node_modules) || File.file?(package_lock))
      rescue ArgumentError, IOError, SystemCallError
        false
      end

      def engine_label
        if node_available?
          version = node_version || "Node.js"
          "#{version} | DOCX: docx.js | PDF: react-pdf"
        else
          "Ruby | DOCX: Caracal | PDF: HexaPDF"
        end
      end

      def capture(*command)
        Open3.capture2(*command)
      rescue Errno::ENOENT, IOError, SystemCallError
        [nil, nil]
      end
      private_class_method :capture
    end
  end
end
