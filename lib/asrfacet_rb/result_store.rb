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

require "concurrent"
require "set"
require "time"

module ASRFacet
  class ResultStore
    UNIQUE_CATEGORIES = %i[
      subdomains
      ips
      js_endpoints
      candidate_subdomains
      wildcard_ips
    ].freeze

    def initialize
      @data = Concurrent::Map.new
      @ports = Concurrent::Map.new { |hash, key| hash[key] = Concurrent::Array.new }
    end

    def add(category, item)
      bucket = bucket_for(category)
      normalized_item = normalize_item(item)
      if bucket.is_a?(Concurrent::Set)
        bucket.add(normalized_item)
      else
        bucket << normalized_item unless bucket.include?(normalized_item)
      end
      track_open_port(normalized_item) if category.to_sym == :open_ports
      normalized_item
    rescue ASRFacet::Error
      nil
    end

    def all(category)
      bucket = @data[category.to_sym]
      bucket ? bucket.to_a : []
    rescue ASRFacet::Error
      []
    end

    def to_h
      hash = {}
      @data.each_pair do |key, values|
        hash[key] = values.to_a
      end
      hash[:ports] = ports
      hash
    rescue ASRFacet::Error
      {}
    end

    def summary
      stats
    rescue ASRFacet::Error
      {}
    end

    def add_subdomain(subdomain)
      add(:subdomains, subdomain.to_s.downcase.strip)
    end

    def add_ip(ip)
      add(:ips, ip.to_s.strip)
    end

    def add_port(ip, port, banner: nil, service: nil)
      add(:open_ports, { host: ip, port: port, banner: banner, service: service })
    end

    def add_finding(finding)
      add(:findings, finding)
    end

    def add_http_result(host, result)
      add(:http_responses, normalize_item(result).merge(host: host))
    end

    def add_js_endpoint(endpoint)
      add(:js_endpoints, endpoint)
    end

    def add_error(source:, message:)
      add(:errors, { source: source, message: message, time: Time.now.iso8601 })
    end

    def subdomains
      all(:subdomains).sort
    end

    def ips
      all(:ips).sort
    end

    def ports
      hash = {}
      @ports.each_pair do |host, entries|
        hash[host] = entries.to_a
      end
      hash
    end

    def findings
      all(:findings)
    end

    def js_endpoints
      all(:js_endpoints).sort
    end

    def errors
      all(:errors)
    end

    def stats
      hash = {}
      @data.each_pair do |key, values|
        hash[key] = values.size
      end
      hash
    end

    private

    def bucket_for(category)
      key = category.to_sym
      @data.compute_if_absent(key) do
        UNIQUE_CATEGORIES.include?(key) ? Concurrent::Set.new : Concurrent::Array.new
      end
    end

    def normalize_item(item)
      if item.respond_to?(:to_h) && !item.is_a?(Hash)
        item.to_h
      else
        item
      end
    rescue ASRFacet::Error
      item
    end

    def track_open_port(item)
      entry = normalize_item(item)
      host = entry[:host].to_s
      return nil if host.empty?

      @ports[host] << {
        port: entry[:port],
        banner: entry[:banner],
        service: entry[:service]
      }
    rescue ASRFacet::Error
      nil
    end
  end
end
