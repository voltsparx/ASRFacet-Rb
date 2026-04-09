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
  VERSION = begin
    root = File.expand_path("../..", __dir__)
    version_file = File.join(root, "VERSION")
    version_md_file = File.join(root, "VERSION.md")

    if File.file?(version_file)
      raw = File.read(version_file).strip
      semver = raw[/\A([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?)\z/, 1]
      c_header = raw[/VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?)"/, 1]
      semver || c_header || "1.0.0"
    elsif File.file?(version_md_file)
      content = File.read(version_md_file)
      matched = content.match(/VERSION\s*=\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?)/i)
      matched ? matched[1] : "1.0.0"
    else
      "1.0.0"
    end
  rescue StandardError
    "1.0.0"
  end.freeze
end
