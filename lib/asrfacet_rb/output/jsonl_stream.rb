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

require "fileutils"
require "json"
require "time"

module ASRFacet
  module Output
    class JsonlStream
      attr_reader :path

      def initialize(target, base_dir: File.join("output", "streams"))
        safe_target = target.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_").gsub(".", "_")
        @path = File.join(File.expand_path(base_dir.to_s), "#{safe_target.empty? ? 'scan' : safe_target}.jsonl")
        @mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
      rescue StandardError
        @path = File.expand_path(File.join("~", ".asrfacet_rb", "output", "streams", "scan.jsonl"))
        @mutex = Mutex.new
      end

      def write(entry_type, payload)
        line = {
          type: entry_type.to_s,
          timestamp: Time.now.utc.iso8601,
          payload: normalize(payload)
        }

        @mutex.synchronize do
          File.open(@path, "a") { |file| file.puts(JSON.generate(line)) }
        end
        true
      rescue StandardError
        nil
      end

      private

      def normalize(value)
        if value.respond_to?(:to_h) && !value.is_a?(Hash)
          normalize(value.to_h)
        elsif value.is_a?(Hash)
          value.each_with_object({}) { |(key, nested), memo| memo[key] = normalize(nested) }
        elsif value.is_a?(Array)
          value.map { |entry| normalize(entry) }
        else
          value
        end
      rescue StandardError
        value.to_s
      end
    end
  end
end
