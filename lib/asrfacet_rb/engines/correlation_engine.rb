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

require "digest/md5"
require "set"

module ASRFacet
  module Engines
    class CorrelationEngine
      FAVICON_HASH_PATH = "/favicon.ico"

      def initialize(client: ASRFacet::HTTP::RetryableClient.new)
        @client = client
      end

      def run(result_store, knowledge_graph)
        @result_store = normalize_store(result_store)
        @graph = knowledge_graph

        relationships = []
        relationships.concat(correlate_tls_reuse(@result_store))
        relationships.concat(correlate_favicon(@result_store))
        relationships.concat(correlate_response_similarity(@result_store))
        relationships.concat(correlate_ip_neighbors(@result_store, @graph))
        relationships
      rescue StandardError
        []
      end

      def correlate_tls_reuse(result_store)
        grouped = Array(result_store[:certs]).group_by do |cert|
          entry = symbolize_keys(cert)
          [entry[:subject].to_s, Array(entry[:sans]).sort].join("|")
        end

        grouped.values.filter_map do |certs|
          hosts = certs.map { |entry| symbolize_keys(entry)[:host].to_s }.reject(&:empty?).uniq.sort
          next unless hosts.size > 1

          connect_group(hosts, :shared_cert)
          {
            type: :tls_reuse,
            shared_by: hosts,
            cert_subject: symbolize_keys(certs.first)[:subject].to_s
          }
        end
      rescue StandardError
        []
      end

      def correlate_favicon(result_store)
        groups = Hash.new { |hash, key| hash[key] = [] }

        Array(result_store[:http_responses]).each do |response|
          entry = symbolize_keys(response)
          url = "#{entry[:url].to_s.sub(%r{/+\z}, '')}#{FAVICON_HASH_PATH}"
          favicon = @client.get(url)
          next if favicon.nil? || favicon.body.to_s.empty?

          groups[Digest::MD5.hexdigest(favicon.body.to_s)] << entry[:host].to_s
        rescue StandardError
          nil
        end

        groups.filter_map do |digest, hosts|
          uniq_hosts = hosts.reject(&:empty?).uniq.sort
          next unless uniq_hosts.size > 1

          connect_group(uniq_hosts, :shared_favicon)
          { type: :favicon_match, hash: digest, hosts: uniq_hosts }
        end
      rescue StandardError
        []
      end

      def correlate_response_similarity(result_store)
        groups = Array(result_store[:http_responses]).group_by do |response|
          entry = symbolize_keys(response)
          [entry[:title].to_s, (entry[:status] || entry[:status_code]).to_i]
        end

        groups.values.filter_map do |responses|
          hosts = responses.map { |entry| symbolize_keys(entry)[:host].to_s }.reject(&:empty?).uniq.sort
          next unless hosts.size > 1

          first = symbolize_keys(responses.first)
          connect_group(hosts, :response_clone)
          { type: :response_clone, hosts: hosts, title: first[:title].to_s, status: (first[:status] || first[:status_code]).to_i }
        end
      rescue StandardError
        []
      end

      def correlate_ip_neighbors(result_store, knowledge_graph)
        return [] if knowledge_graph.nil?

        grouped = Hash.new { |hash, key| hash[key] = Set.new }
        Array(result_store[:dns]).each do |record|
          entry = symbolize_keys(record)
          next unless %i[a aaaa].include?(entry[:type].to_sym)

          grouped[entry[:value].to_s] << entry[:host].to_s
        rescue StandardError
          nil
        end

        grouped.filter_map do |ip, hosts|
          next unless hosts.size > 1

          host_list = hosts.to_a.sort
          connect_group(host_list, :shared_ip)
          knowledge_graph.add_node(ip, type: :ip, data: { shared_by: host_list })
          { type: :shared_ip, ip: ip, domains: host_list }
        end
      rescue StandardError
        []
      end

      private

      def normalize_store(result_store)
        return result_store.to_h if result_store.respond_to?(:to_h) && !result_store.is_a?(Hash)

        symbolize_keys(result_store)
      rescue StandardError
        {}
      end

      def connect_group(hosts, relation)
        hosts.combination(2) do |left, right|
          @graph&.add_edge(left, right, relation: relation)
          @graph&.add_edge(right, left, relation: relation)
        rescue StandardError
          nil
        end
      rescue StandardError
        nil
      end

      def symbolize_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize_keys(nested)
          end
        when Array
          value.map { |entry| symbolize_keys(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end
    end
  end
end
