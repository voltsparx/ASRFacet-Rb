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
  module Core
    module WarningFilter
      IGNORED_PATTERNS = [
        /fiddle used to be loaded from the standard library/i
      ].freeze

      module WarningShim
        def warn(message, category: nil, **kwargs)
          text = message.to_s
          return if ASRFacet::Core::WarningFilter.ignore?(text)

          super
        rescue StandardError
          nil
        end
      end

      module_function

      def install!
        return if @installed

        Warning.singleton_class.prepend(WarningShim)
        @installed = true
      rescue StandardError
        nil
      end

      def ignore?(message)
        text = message.to_s
        IGNORED_PATTERNS.any? { |pattern| pattern.match?(text) }
      rescue StandardError
        false
      end
    end
  end
end
