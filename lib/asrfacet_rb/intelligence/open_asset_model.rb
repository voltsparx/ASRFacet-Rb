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

require "digest"
require "ipaddr"
require "time"

module ASRFacet
  module Intelligence
    module OpenAssetModel
      ASSET_TYPES = %i[
        fqdn ip_address netblock asn as_desc domain
        email person organization location phone
        certificate url service port technology
      ].freeze

      RELATION_TYPES = %i[
        a_record aaaa_record cname_record mx_record
        ns_record txt_record srv_record soa_record
        ptr_record contains managed_by registered_to
        has_certificate san_entry subdomain_of port_of
        service_of resolves_to
      ].freeze

      Asset = Struct.new(
        :id,
        :type,
        :value,
        :properties,
        :found_at,
        :source,
        :confidence,
        keyword_init: true
      ) do
        def to_h
          {
            id: id.to_s,
            type: type.to_sym,
            value: value,
            properties: properties.is_a?(Hash) ? properties : {},
            found_at: found_at.to_s,
            source: source.to_s,
            confidence: confidence.to_f
          }
        end
      end

      Relation = Struct.new(
        :from_id,
        :to_id,
        :type,
        :properties,
        :found_at,
        :source,
        keyword_init: true
      ) do
        def to_h
          {
            from_id: from_id.to_s,
            to_id: to_id.to_s,
            type: type.to_sym,
            properties: properties.is_a?(Hash) ? properties : {},
            found_at: found_at.to_s,
            source: source.to_s
          }
        end
      end

      module_function

      def make(type:, value:, source:, properties: {})
        normalized_type = normalize_type(type, ASSET_TYPES)
        normalized_value = normalize_value(normalized_type, value)
        normalized_properties = normalize_hash(properties)

        Asset.new(
          id: asset_id(normalized_type, normalized_value),
          type: normalized_type,
          value: normalized_value,
          properties: normalized_properties,
          found_at: normalized_properties[:found_at].to_s.empty? ? Time.now.utc.iso8601 : normalized_properties[:found_at].to_s,
          source: source.to_s,
          confidence: extract_confidence(normalized_properties)
        )
      end

      def make_relation(from_id:, to_id:, type:, source:, properties: {})
        normalized_type = normalize_type(type, RELATION_TYPES)
        normalized_properties = normalize_hash(properties)

        Relation.new(
          from_id: from_id.to_s,
          to_id: to_id.to_s,
          type: normalized_type,
          properties: normalized_properties,
          found_at: normalized_properties[:found_at].to_s.empty? ? Time.now.utc.iso8601 : normalized_properties[:found_at].to_s,
          source: source.to_s
        )
      end

      def asset_id(type, value)
        Digest::SHA256.hexdigest("#{type}:#{value}")[0, 24]
      end

      def normalize_type(type, allowed_types)
        candidate = type.to_sym
        raise ASRFacet::ParseError, "Unsupported asset or relation type: #{type}" unless allowed_types.include?(candidate)

        candidate
      rescue NoMethodError
        raise ASRFacet::ParseError, "Unsupported asset or relation type: #{type}"
      end

      def normalize_value(type, value)
        text = value.to_s.strip
        case type
        when :fqdn, :domain, :email, :technology, :service, :url
          text.downcase
        when :asn
          text.upcase.start_with?("AS") ? text.upcase : "AS#{text.upcase}"
        when :netblock
          IPAddr.new(text).to_s + "/#{IPAddr.new(text).prefix}" rescue text.downcase
        when :ip_address
          IPAddr.new(text).to_s
        when :port
          text.to_i.to_s
        else
          text
        end
      rescue IPAddr::InvalidAddressError
        text.downcase
      end
      private_class_method :normalize_value

      def normalize_hash(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = normalize_hash(nested)
          end
        when Array
          value.map { |entry| normalize_hash(entry) }
        else
          value
        end
      end
      private_class_method :normalize_hash

      def extract_confidence(properties)
        value = properties[:confidence]
        score = value.nil? ? 1.0 : value.to_f
        return 0.0 if score.negative?
        return 1.0 if score > 1.0

        score
      rescue NoMethodError, TypeError
        1.0
      end
      private_class_method :extract_confidence
    end

    OAM = OpenAssetModel
  end
end
