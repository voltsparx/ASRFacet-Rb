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
require "whois"

module ASRFacet
  module Intelligence
    module Enrichment
      class WhoisEnricher
        DEFAULT_TTL = 3600

        def initialize(cache_ttl: DEFAULT_TTL, logger: nil, whois_client: nil, clock: nil)
          @cache_ttl = cache_ttl.to_i.positive? ? cache_ttl.to_i : DEFAULT_TTL
          @logger = logger
          @whois_client = whois_client || Whois::Client.new
          @clock = clock || -> { Time.now.utc }
          @cache = Concurrent::Map.new
        end

        def enrich(domain, graph:)
          target = domain.to_s.downcase
          data = cached_lookup(target)
          return {} if data.empty?

          domain_asset = graph.add_asset(
            ASRFacet::Intelligence::OAM.make(
              type: :domain,
              value: target,
              source: "whois_enricher",
              properties: data
            )
          )

          Array(data[:nameservers]).each do |nameserver|
            ns_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(type: :fqdn, value: nameserver, source: "whois_enricher", properties: {})
            )
            graph.add_relation(from: domain_asset, to: ns_asset, type: :ns_record, source: "whois_enricher")
          end

          registrant_name = data[:registrant].to_s
          unless registrant_name.empty?
            organization = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(
                type: :organization,
                value: registrant_name,
                source: "whois_enricher",
                properties: { registrar: data[:registrar] }
              )
            )
            graph.add_relation(from: domain_asset, to: organization, type: :registered_to, source: "whois_enricher")
          end

          Array(data[:emails]).each do |email|
            email_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(type: :email, value: email, source: "whois_enricher", properties: {})
            )
            graph.add_relation(from: domain_asset, to: email_asset, type: :registered_to, source: "whois_enricher")
          end

          data
        rescue StandardError => e
          log_warning("WHOIS enrichment failed for #{domain}: #{e.message}")
          {}
        end

        private

        def cached_lookup(domain)
          cached = @cache[domain]
          return cached[:data] if cached && (@clock.call - cached[:fetched_at]) < @cache_ttl

          data = lookup(domain)
          @cache[domain] = { fetched_at: @clock.call, data: data }
          data
        end

        def lookup(domain)
          record = if @whois_client.respond_to?(:lookup)
                     @whois_client.lookup(domain)
                   else
                     Whois.whois(domain)
                   end
          extract_data(record)
        rescue StandardError => e
          log_warning("WHOIS lookup failed for #{domain}: #{e.message}")
          {}
        end

        def extract_data(record)
          parser = record.respond_to?(:parser) ? record.parser : record
          content = record.respond_to?(:content) ? record.content.to_s : parser.to_s

          {
            registrar: first_value(parser, content, %w[registrar_name registrar], /^Registrar:\s*(.+)$/i),
            registrant: registrant_name(parser, content),
            created_at: time_value(parser, content, %w[created_on created_date created], /^Creation Date:\s*(.+)$/i),
            updated_at: time_value(parser, content, %w[updated_on updated_date updated], /^Updated Date:\s*(.+)$/i),
            expires_at: time_value(parser, content, %w[expires_on expiration_date expires], /^Registry Expiry Date:\s*(.+)$/i),
            nameservers: nameservers(parser, content),
            status: statuses(parser, content),
            emails: emails(parser, content)
          }.delete_if { |_key, value| value.nil? || value == [] || value.to_s.empty? }
        end

        def registrant_name(parser, content)
          first_value(
            parser,
            content,
            %w[registrant_name registrant organization registrant_organization],
            /^Registrant(?: Organization| Name)?:\s*(.+)$/i
          )
        end

        def nameservers(parser, content)
          values = []
          values.concat(Array(parser_send(parser, :nameservers)).map { |entry| entry.respond_to?(:name) ? entry.name : entry })
          values.concat(content.scan(/^Name Server:\s*(.+)$/i).flatten)
          values.map { |entry| entry.to_s.downcase.strip }.reject(&:empty?).uniq.sort
        rescue StandardError
          []
        end

        def statuses(parser, content)
          values = []
          values.concat(Array(parser_send(parser, :status)))
          values.concat(content.scan(/^Status:\s*(.+)$/i).flatten)
          values.map { |entry| entry.to_s.strip }.reject(&:empty?).uniq.sort
        rescue StandardError
          []
        end

        def emails(parser, content)
          values = []
          %i[admin_contacts technical_contacts registrant_contacts contacts].each do |method_name|
            Array(parser_send(parser, method_name)).each do |contact|
              values.concat(Array(contact_emails(contact)))
            end
          end
          values.concat(content.scan(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i))
          values.map { |entry| entry.to_s.downcase.strip }.reject(&:empty?).uniq.sort
        rescue StandardError
          []
        end

        def contact_emails(contact)
          return [] if contact.nil?

          if contact.respond_to?(:email)
            Array(contact.email)
          elsif contact.respond_to?(:emails)
            Array(contact.emails)
          else
            []
          end
        end

        def time_value(parser, content, methods, regex)
          value = methods.lazy.map { |method_name| parser_send(parser, method_name.to_sym) }.find { |entry| !entry.nil? && entry.to_s != "" }
          value ||= content[regex, 1]
          value.to_s.empty? ? nil : value.to_s
        end

        def first_value(parser, content, methods, regex)
          value = methods.lazy.map { |method_name| parser_send(parser, method_name.to_sym) }.find { |entry| !entry.nil? && entry.to_s != "" }
          value ||= content[regex, 1]
          value.to_s.empty? ? nil : value.to_s.strip
        end

        def parser_send(parser, method_name)
          return nil unless parser.respond_to?(method_name)

          parser.public_send(method_name)
        rescue StandardError
          nil
        end

        def log_warning(message)
          if @logger&.respond_to?(:warn)
            @logger.warn(message)
          elsif @logger&.respond_to?(:print_warning)
            @logger.print_warning(message)
          end
        rescue StandardError
          nil
        end
      end
    end
  end
end
