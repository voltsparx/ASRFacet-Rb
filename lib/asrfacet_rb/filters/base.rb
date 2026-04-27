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
  module Filters
    class Base
      def self.priority(value = nil)
        value.nil? ? (@priority || 50) : @priority = value
      end

      def self.filter_name(value = nil)
        return @filter_name || default_name if value.nil?

        @filter_name = value.to_s
      end

      def self.description(value = nil)
        return @description || "Session filter" if value.nil?

        @description = value.to_s
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

      def self.default_name
        name.to_s.split("::").last.to_s.gsub(/Filter$/, "").gsub(/([a-z])([A-Z])/, '\1_\2').downcase
      rescue StandardError
        "filter"
      end

      def self.filter_family(value = nil)
        return @filter_family || :session if value.nil?

        @filter_family = value.to_sym
      end

      def self.filter_name_list
        [filter_name]
      rescue StandardError
        []
      end

      def self.inherited(subclass)
        super
        subclass.filter_family(:session)
      rescue StandardError
        nil
      end

      def self.plugin_name
        filter_name
      end

      def self.metadata
        {
          name: filter_name,
          title: filter_name.to_s.split("_").map(&:capitalize).join(" "),
          family: filter_family,
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

      def priority
        self.class.priority
      end

      def apply(context)
        context
      end
    end
  end
end
