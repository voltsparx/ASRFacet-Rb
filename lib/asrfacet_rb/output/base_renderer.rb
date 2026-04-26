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

require "fileutils"
require "json"
require "time"

module ASRFacet
  module Output
    class BaseRenderer
      attr_reader :store, :target, :options

      def initialize(result_store, target, options = {})
        @store = result_store
        @target = target.to_s
        @options = options || {}
      end

      def render(_output_path)
        raise NotImplementedError, "#{self.class}#render must be implemented"
      end

      protected

      def timestamp
        Time.now.utc.strftime("%Y-%m-%d %H:%M:%S UTC")
      end

      def iso_timestamp
        Time.now.utc.iso8601
      end

      def version
        ASRFacet::VERSION
      end

      def report_title
        "ASRFacet-Rb Reconnaissance Report"
      end

      def severity_order
        {
          "critical" => 0,
          "high" => 1,
          "medium" => 2,
          "low" => 3,
          "informational" => 4,
          "info" => 4
        }
      end

      def sorted_findings
        findings.sort_by do |finding|
          [
            severity_order.fetch(finding[:severity].to_s.downcase, 99),
            finding_timestamp(finding),
            finding[:title].to_s
          ]
        end
      end

      def write!(path, content)
        FileUtils.mkdir_p(File.dirname(path))
        mode = content.is_a?(String) ? "w" : "wb"
        File.open(path, mode) { |file| file.write(content) }
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
        raise ASRFacet::Error, e.message
      end

      def log_success(format, path)
        ASRFacet::Core::ThreadSafe.print_good("#{format} report written -> #{path}")
      rescue ASRFacet::Error, IOError, NoMethodError
        puts "[ok] #{format} report written -> #{path}"
      end

      def log_error(format, message)
        ASRFacet::Core::ThreadSafe.print_error("#{format} render failed: #{message}")
      rescue ASRFacet::Error, IOError, NoMethodError
        warn "[error] #{format} render failed: #{message}"
      end

      def report_payload
        {
          meta: {
            tool: "ASRFacet-Rb",
            version: version,
            target: target,
            generated_at: iso_timestamp,
            title: report_title,
            engine: options[:engine_label].to_s
          },
          stats: stats,
          graph: graph_payload,
          subdomains: subdomain_rows,
          ips: ip_rows,
          ports: port_rows,
          findings: sorted_findings,
          js_endpoints: js_endpoint_rows,
          errors: error_rows,
          charts: charts
        }
      end

      def stats
        derived = {
          subdomains: subdomains.size,
          ips: ips.size,
          ports: port_rows.size,
          findings: findings.size,
          js_endpoints: js_endpoint_rows.size,
          errors: error_rows.size
        }
        aggregate = if store.respond_to?(:to_h)
                      store.to_h.each_with_object({}) do |(key, value), memo|
                        memo[key.to_sym] = value.is_a?(Array) ? value.size : value
                      end
                    else
                      {}
                    end
        aggregate.merge(derived)
      end

      def charts
        options[:charts].is_a?(Hash) ? options[:charts] : {}
      end

      def graph_payload
        graph = options[:asset_graph]
        return {} if graph.nil?
        return graph.to_h if graph.respond_to?(:to_h)

        {}
      rescue ASRFacet::Error, NoMethodError, TypeError
        {}
      end

      def subdomains
        Array(fetch_store_array(:subdomains)).map { |entry| entry.to_s.strip }.reject(&:empty?).uniq.sort
      end

      def ips
        Array(fetch_store_array(:ips)).map { |entry| entry.to_s.strip }.reject(&:empty?).uniq.sort
      end

      def findings
        Array(fetch_store_array(:findings)).map { |entry| symbolize_hash(entry) }
      end

      def errors
        Array(fetch_store_array(:errors)).map { |entry| symbolize_hash(entry) }
      end

      def js_endpoints
        values = if store.respond_to?(:all)
                   Array(store.all(:js_endpoints))
                 else
                   fetch_store_array(:js_endpoints)
                 end
        values.map do |entry|
          case entry
          when Hash
            symbolize_hash(entry)
          else
            { endpoint: entry.to_s }
          end
        end
      end

      def port_rows
        port_hash = fetch_store_hash(:ports)
        rows = port_hash.each_with_object([]) do |(host, entries), memo|
          Array(entries).each do |entry|
            normalized = symbolize_hash(entry)
            memo << {
              host: host.to_s,
              port: normalized[:port].to_i,
              service: normalized[:service].to_s,
              banner: normalized[:banner].to_s
            }
          end
        end
        rows.sort_by { |entry| [entry[:host], entry[:port], entry[:service]] }
      end

      def subdomain_rows
        source_map = Hash.new { |hash, key| hash[key] = [] }
        Array(fetch_store_array(:subdomains_with_sources)).each do |entry|
          normalized = symbolize_hash(entry)
          host = normalized[:host].to_s
          source = normalized[:source].to_s
          next if host.empty? || source.empty?

          source_map[host] << source
        end

        subdomains.map do |host|
          {
            host: host,
            sources: source_map[host].uniq.sort
          }
        end
      end

      def ip_rows
        counts = port_rows.group_by { |entry| entry[:host] }
        ips.map do |ip|
          {
            ip: ip,
            ports: Array(counts[ip]).size,
            class: ip_class(ip)
          }
        end
      end

      def js_endpoint_rows
        js_endpoints.map do |entry|
          normalized = symbolize_hash(entry)
          endpoint = normalized[:endpoint].to_s
          endpoint = normalized[:url].to_s if endpoint.empty?
          {
            endpoint: endpoint,
            method: normalized[:method].to_s.empty? ? "GET" : normalized[:method].to_s.upcase,
            source: normalized[:source].to_s.empty? ? normalized[:discovered_from].to_s : normalized[:source].to_s
          }
        end
      end

      def error_rows
        errors.map do |entry|
          {
            source: entry[:source].to_s,
            message: entry[:message].to_s.empty? ? entry[:reason].to_s : entry[:message].to_s,
            time: entry[:time].to_s.empty? ? entry[:timestamp].to_s : entry[:time].to_s
          }
        end
      end

      def finding_timestamp(finding)
        raw = finding[:found_at] || finding[:time] || finding[:timestamp]
        return Time.at(0).utc.iso8601 if raw.nil?

        case raw
        when Time
          raw.utc.iso8601
        else
          Time.parse(raw.to_s).utc.iso8601
        end
      rescue ArgumentError, TypeError
        Time.at(0).utc.iso8601
      end

      def ip_class(ip)
        octets = ip.to_s.split(".").map(&:to_i)
        return "Other" unless octets.size == 4

        first = octets[0]
        return "Private" if first == 10
        return "Private" if first == 172 && octets[1].between?(16, 31)
        return "Private" if first == 192 && octets[1] == 168
        return "Loopback" if first == 127
        return "Link Local" if first == 169 && octets[1] == 254
        return "Class A" if first.between?(1, 126)
        return "Class B" if first.between?(128, 191)
        return "Class C" if first.between?(192, 223)

        "Other"
      rescue NoMethodError, TypeError
        "Other"
      end

      def symbolize_hash(value)
        return {} unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, nested), memo|
          memo[key.to_sym] = nested
        end
      rescue NoMethodError, TypeError
        {}
      end

      def fetch_store_array(method_name)
        if store.respond_to?(method_name)
          Array(store.public_send(method_name))
        elsif store.respond_to?(:all)
          Array(store.all(method_name))
        else
          []
        end
      rescue ASRFacet::Error, NoMethodError, TypeError
        []
      end

      def fetch_store_hash(method_name)
        value = if store.respond_to?(method_name)
                  store.public_send(method_name)
                elsif store.respond_to?(:to_h)
                  store.to_h[method_name]
                else
                  {}
                end
        value.is_a?(Hash) ? value : {}
      rescue ASRFacet::Error, NoMethodError, TypeError
        {}
      end
    end
  end
end
