# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
  module Scanner
    module ScanTypes
      class ServiceScan < ConnectScan
        def probe(host, port)
          result = super
          return result unless result.open?

          detected = @context.version_detector.detect(host, port, proto: :tcp)
          return result unless detected

          result.service = detected[:service] if detected[:service]
          result.version = detected[:version] if detected[:version]
          result.extra = detected[:extra] if detected[:extra]
          result.cpe = detected[:cpe] if detected[:cpe]
          result.banner = detected[:banner] if detected[:banner]
          result
        end
      end
    end
  end
end
