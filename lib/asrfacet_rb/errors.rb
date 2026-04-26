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
  class Error < StandardError; end
  class NetworkError < Error; end
  class ScopeViolation < Error; end
  class RateLimitError < Error; end
  class SourceError < Error; end
  class ParseError < Error; end
  class KeyStoreError < Error; end
  class PluginError < Error; end
end
