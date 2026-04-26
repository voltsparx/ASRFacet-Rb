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
  module Plugins
    class Base
      def self.priority(value = nil)
        value.nil? ? (@priority || 50) : @priority = value
      end

      def self.handles(*types)
        types.empty? ? (@handles || []) : @handles = types.map(&:to_sym)
      end

      def priority
        self.class.priority
      end

      def handles?(event_type)
        self.class.handles.include?(event_type.to_sym)
      end

      def process(_asset, _context, _bus)
        raise NotImplementedError, "#{self.class}#process must be implemented"
      end
    end
  end
end
