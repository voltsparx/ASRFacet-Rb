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
  module Execution
    module Contract
      ENGINE_OWNER_PATTERN = /
        (?:^|::)(?:Engines|Busters|Passive)(?:::|$)|
        (?:Engine|Buster|Source)\z
      /x.freeze

      ORCHESTRATOR_GUIDANCE = "Scheduler decides, engines execute, investigators react, and fusion layers store.".freeze

      class OwnershipError < StandardError; end

      module_function

      def normalize_owner(owner)
        value = owner.to_s.strip
        value.empty? ? "standalone" : value
      rescue StandardError
        "standalone"
      end

      def validate_scheduler_owner!(owner)
        normalized = normalize_owner(owner)
        return normalized unless engine_owned?(normalized)

        raise OwnershipError,
              "Scheduler ownership belongs to an orchestrator, not #{normalized}. #{ORCHESTRATOR_GUIDANCE}"
      end

      def engine_owned?(owner)
        normalize_owner(owner).match?(ENGINE_OWNER_PATTERN)
      rescue StandardError
        false
      end

      def summary
        ORCHESTRATOR_GUIDANCE
      end
    end
  end
end
