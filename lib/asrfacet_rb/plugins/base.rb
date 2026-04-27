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

      def self.plugin_name(value = nil)
        return @plugin_name || default_plugin_name if value.nil?

        @plugin_name = value.to_s
      end

      def self.description(value = nil)
        return @description || "Session plugin" if value.nil?

        @description = value.to_s
      end

      def self.plugin_family(value = nil)
        return @plugin_family || :event if value.nil?

        @plugin_family = value.to_sym
      end

      def self.category(value = nil)
        return @category || "general" if value.nil?

        @category = value.to_s
      end

      def self.modes(*values)
        return @modes || [] if values.empty?

        @modes = values.flatten.compact.map { |entry| entry.to_s.downcase }
      end

      def self.aliases(*values)
        return @aliases || [] if values.empty?

        @aliases = values.flatten.compact.map { |entry| entry.to_s.downcase }
      end

      def self.tags(*values)
        return @tags || [] if values.empty?

        @tags = values.flatten.compact.map { |entry| entry.to_s.downcase }
      end

      def self.handles(*types)
        types.empty? ? (@handles || []) : @handles = types.map(&:to_sym)
      end

      def self.default_plugin_name
        name.to_s.split("::").last.to_s.gsub(/Plugin$/, "").gsub(/([a-z])([A-Z])/, '\1_\2').downcase
      rescue StandardError
        "plugin"
      end

      def self.inherited(subclass)
        super
        subclass.plugin_family(:event)
      rescue StandardError
        nil
      end

      def priority
        self.class.priority
      end

      def self.metadata
        {
          name: plugin_name,
          title: plugin_name.to_s.split("_").map(&:capitalize).join(" "),
          family: plugin_family,
          category: category,
          description: description,
          modes: modes,
          aliases: aliases,
          tags: tags,
          priority: priority
        }
      rescue StandardError
        {}
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
