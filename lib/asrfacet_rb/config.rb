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

require "yaml"

module ASRFacet
  module Config
    DEFAULTS = {
      "threads" => {
        "default" => 50,
        "dns" => 100,
        "http" => 50,
        "paths" => 20,
        "dir" => 40
      },
      "timeouts" => {
        "dns" => 2,
        "port" => 1.5,
        "http" => 5,
        "ssl" => 5
      },
      "wordlists" => {
        "subdomain" => "wordlists/subdomains_small.txt",
        "paths" => "wordlists/paths_common.txt"
      },
      "output" => {
        "directory" => "~/.asrfacet_rb/output",
        "format" => "cli"
      },
      "http" => {
        "user_agent" => "ASRFacet-Rb/#{ASRFacet::VERSION}",
        "max_retries" => 3,
        "follow_redirects" => true,
        "max_redirects" => 5,
        "verify_ssl" => false
      }
    }.freeze

    module_function

    def load(overrides = {})
      config = deep_merge(DEFAULTS, load_yaml(project_config_path))
      config = deep_merge(config, load_yaml(user_config_path))
      deep_merge(config, stringify_keys(overrides))
    rescue StandardError
      DEFAULTS.dup
    end

    def fetch(*keys, config: load)
      keys.reduce(config) { |memo, key| memo.fetch(key.to_s) }
    rescue StandardError
      nil
    end

    def project_config_path
      File.expand_path(File.join(__dir__, "..", "..", "config", "default.yml"))
    rescue StandardError
      ""
    end

    def user_config_path
      File.expand_path("~/.asrfacet_rb/config.yml")
    rescue StandardError
      ""
    end

    def load_yaml(path)
      return {} unless File.file?(path)

      YAML.safe_load(File.read(path), permitted_classes: [Symbol], aliases: true) || {}
    rescue StandardError
      {}
    end
    private_class_method :load_yaml

    def deep_merge(base, extra)
      stringify_keys(base).merge(stringify_keys(extra)) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge(old_value, new_value)
        else
          new_value
        end
      end
    rescue StandardError
      stringify_keys(base)
    end
    private_class_method :deep_merge

    def stringify_keys(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested), memo|
          memo[key.to_s] = stringify_keys(nested)
        end
      when Array
        value.map { |entry| stringify_keys(entry) }
      else
        value
      end
    rescue StandardError
      {}
    end
    private_class_method :stringify_keys
  end
end
