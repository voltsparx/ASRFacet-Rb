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
    module PluginSDK
      @registry = Hash.new { |hash, key| hash[key] = {} }
      @mutex = Mutex.new

      class << self
        def included(base)
          base.extend(ClassMethods)
          register(base)
        rescue StandardError
          nil
        end

        def register(klass)
          return nil if klass.nil?

          type = plugin_type_for(klass)
          name = plugin_name_for(klass)
          @mutex.synchronize do
            @registry[type][name] = klass
          end
          klass
        rescue StandardError
          nil
        end

        def all(type: nil)
          @mutex.synchronize do
            return @registry.values.flat_map(&:values).uniq if type.nil?

            @registry[type.to_sym].values.uniq
          end
        rescue StandardError
          []
        end

        def find(name)
          normalized = name.to_s.downcase
          @mutex.synchronize do
            @registry.values.each do |entries|
              klass = entries[normalized]
              return klass unless klass.nil?
            end
            nil
          end
        rescue StandardError
          nil
        end

        def register_namespace(namespace, type: :engine)
          namespace.constants.each do |const_name|
            klass = namespace.const_get(const_name)
            next unless klass.is_a?(Class)

            register(klass) if type.nil? || plugin_type_for(klass) == type.to_sym
          rescue StandardError
            nil
          end
        rescue StandardError
          nil
        end

        def plugin_name_for(klass)
          return klass.plugin_name if klass.respond_to?(:plugin_name)

          klass.name.to_s.split("::").last.to_s.gsub(/Engine|Buster|Source|Formatter/, "").downcase
        rescue StandardError
          "plugin"
        end

        def plugin_type_for(klass)
          return klass.plugin_type if klass.respond_to?(:plugin_type)

          namespace = klass.name.to_s.split("::")[-2].to_s.downcase
          case namespace
          when "passive" then :passive_source
          when "busters" then :buster
          when "output" then :formatter
          else :engine
          end
        rescue StandardError
          :engine
        end
      end

      module ClassMethods
        def inherited(subclass)
          super
          PluginSDK.register(subclass)
        rescue StandardError
          nil
        end

        def plugin_name
          name.to_s.split("::").last.to_s.gsub(/Engine|Buster|Source|Formatter/, "").downcase
        rescue StandardError
          "plugin"
        end

        def plugin_type
          :engine
        rescue StandardError
          :engine
        end

        def depends_on(*deps)
          @dependencies = deps.flatten.compact
        rescue StandardError
          @dependencies = []
        end

        def dependencies
          @dependencies || []
        rescue StandardError
          []
        end
      end

      module DependencyInjector
        module_function

        def inject(instance, logger:, http_client:, event_bus:, config:)
          return instance if instance.nil?

          assign(instance, :logger=, logger)
          assign(instance, :http_client=, http_client)
          assign(instance, :event_bus=, event_bus)
          assign(instance, :config=, config)
          instance
        rescue StandardError
          instance
        end

        def assign(instance, setter, value)
          if instance.respond_to?(setter)
            instance.public_send(setter, value)
          else
            instance.instance_variable_set("@#{setter.to_s.delete_suffix('=').to_s.sub(/\A@/, '')}", value)
          end
        rescue StandardError
          nil
        end
      end
    end
  end
end
