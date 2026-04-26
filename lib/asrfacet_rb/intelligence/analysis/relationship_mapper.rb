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

require "ipaddr"
require_relative "../open_asset_model"

module ASRFacet
  module Intelligence
    module Analysis
      class RelationshipMapper
        def map(graph)
          @graph = graph
          inferred_third_parties = detect_third_parties

          {
            new_assets: infer_certificate_sans.map(&:to_h),
            new_relations: (infer_netblock_links + infer_third_party_links).map(&:to_h),
            third_parties: (inferred_third_parties.empty? ? third_party_assets : inferred_third_parties).map(&:to_h)
          }
        end

        private

        def infer_netblock_links
          created = []

          @graph.find_by_type(:fqdn).each do |fqdn|
            resolved_ips(fqdn).each do |ip_asset|
              containing_netblocks(ip_asset).each do |netblock|
                next if relation_exists?(netblock, ip_asset, :contains)

                created << @graph.add_relation(
                  from: netblock,
                  to: ip_asset,
                  type: :contains,
                  source: "relationship_mapper",
                  properties: { inferred: true, reason: "fqdn_ip_netblock_chain" }
                )
              end
            end
          end

          created.compact
        end

        def infer_certificate_sans
          created = []

          @graph.find_by_type(:certificate).each do |certificate|
            Array(certificate.properties.to_h[:sans]).each do |san|
              fqdn = @graph.find_by_value(:fqdn, san)
              if fqdn.nil?
                fqdn = @graph.add_asset(
                  ASRFacet::Intelligence::OAM.make(
                    type: :fqdn,
                    value: san,
                    source: certificate.source,
                    properties: { inferred: true, inferred_from: certificate.id, confidence: 0.8 }
                  )
                )
                created << fqdn
              end

              next if relation_exists?(certificate, fqdn, :san_entry)

              @graph.add_relation(
                from: certificate,
                to: fqdn,
                type: :san_entry,
                source: "relationship_mapper",
                properties: { inferred: true, reason: "certificate_san" }
              )
            end
          end

          created.compact
        end

        def detect_third_parties
          third_party_assets = []

          (@graph.find_by_type(:asn) + @graph.find_by_type(:netblock)).each do |asset|
            next unless third_party_candidate?(asset)
            next if asset.properties.to_h[:third_party]

            updated = duplicate_asset(asset, asset.properties.to_h.merge(third_party: true, inferred: true))
            third_party_assets << @graph.add_asset(updated)
          end

          @third_party_assets = nil
          third_party_assets.compact
        end

        def infer_third_party_links
          created = []
          detect_third_parties if third_party_assets.empty?

          third_party_assets.each do |asset|
            related_ips(asset).each do |ip_asset|
              next if relation_exists?(ip_asset, asset, :managed_by)

              created << @graph.add_relation(
                from: ip_asset,
                to: asset,
                type: :managed_by,
                source: "relationship_mapper",
                properties: { inferred: true, third_party: true }
              )

              fqdn_neighbors(ip_asset).each do |fqdn|
                next if relation_exists?(fqdn, asset, :managed_by)

                created << @graph.add_relation(
                  from: fqdn,
                  to: asset,
                  type: :managed_by,
                  source: "relationship_mapper",
                  properties: { inferred: true, third_party: true }
                )
              end
            end
          end

          created.compact
        end

        def third_party_assets
          @third_party_assets ||= (@graph.find_by_type(:asn) + @graph.find_by_type(:netblock)).select do |asset|
            asset.properties.to_h[:third_party]
          end
        end

        def relation_exists?(from_asset, to_asset, type)
          @graph.relations_for(from_asset).any? do |relation|
            relation.from_id == from_asset.id && relation.to_id == to_asset.id && relation.type == type.to_sym
          end
        end

        def resolved_ips(fqdn)
          @graph.relations_for(fqdn).filter_map do |relation|
            next unless relation.from_id == fqdn.id && relation.type == :resolves_to

            @graph.find_by_type(:ip_address).find { |asset| asset.id == relation.to_id }
          end
        end

        def containing_netblocks(ip_asset)
          @graph.find_by_type(:netblock).select do |netblock|
            cidr = netblock.properties.to_h[:cidr].to_s
            cidr = netblock.value.to_s if cidr.empty?
            contains_ip?(cidr, ip_asset.value.to_s)
          end
        end

        def contains_ip?(cidr, ip_value)
          IPAddr.new(cidr).include?(IPAddr.new(ip_value))
        rescue IPAddr::InvalidAddressError
          false
        end

        def related_ips(asset)
          if asset.type == :netblock
            @graph.find_by_type(:ip_address).select { |ip_asset| contains_ip?(asset.properties.to_h[:cidr].to_s.empty? ? asset.value.to_s : asset.properties.to_h[:cidr].to_s, ip_asset.value.to_s) }
          else
            @graph.find_by_type(:ip_address).select do |ip_asset|
              ip_asset.properties.to_h[:asn].to_s.casecmp(asset.value.to_s).zero?
            end
          end
        end

        def fqdn_neighbors(ip_asset)
          @graph.neighbors(ip_asset).select { |asset| asset.type == :fqdn }
        end

        def third_party_candidate?(asset)
          owner = [
            asset.properties.to_h[:owner],
            asset.properties.to_h[:organization],
            asset.properties.to_h[:org],
            asset.properties.to_h[:name],
            asset.properties.to_h[:description],
            asset.value
          ].compact.join(" ").downcase
          return false if owner.empty?

          internal_markers.none? { |marker| owner.include?(marker) }
        end

        def internal_markers
          @internal_markers ||= begin
            markers = []
            (@graph.find_by_type(:domain) + @graph.find_by_type(:fqdn)).each do |asset|
              text = asset.value.to_s.downcase
              markers << text
              markers.concat(text.split("."))
            end
            markers.reject { |marker| marker.length < 3 }.uniq
          end
        end

        def duplicate_asset(asset, properties)
          ASRFacet::Intelligence::OpenAssetModel::Asset.new(
            id: asset.id,
            type: asset.type,
            value: asset.value,
            properties: properties,
            found_at: asset.found_at,
            source: asset.source,
            confidence: asset.confidence
          )
        end
      end
    end
  end
end
