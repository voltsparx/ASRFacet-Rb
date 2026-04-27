# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
  module Scanner
    class ProbeDB
      Probe = Struct.new(:name, :proto, :probe_str, :rarity, :wait_ms, :ports, :ssl_ports, :matches, :softmatches, keyword_init: true) do
        def matches_port?(port)
          ports.include?(port.to_i) || ssl_ports.include?(port.to_i)
        end

        def null_probe?
          name == "NULL"
        end

        def to_h
          {
            name: name,
            proto: proto,
            probe_str: probe_str,
            rarity: rarity,
            wait_ms: wait_ms,
            ports: ports,
            ssl_ports: ssl_ports,
            matches: matches,
            softmatches: softmatches
          }
        end
      end

      ROOT = File.expand_path("../../../temp/nmap", __dir__)
      SERVICES_PATH = File.join(ROOT, "nmap-services")
      PROBES_PATH = File.join(ROOT, "nmap-service-probes")
      FALLBACK_SERVICE_NAMES = {
        1 => "tcpmux",
        7 => "echo",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s"
      }.freeze
      FALLBACK_SERVICE_LOOKUP_EXTRAS = {
        [53, :udp] => "domain",
        [67, :udp] => "bootps",
        [68, :udp] => "bootpc",
        [69, :udp] => "tftp",
        [123, :udp] => "ntp",
        [161, :udp] => "snmp",
        [443, :tcp] => "https",
        [1433, :tcp] => "ms-sql-s",
        [1434, :udp] => "ms-sql-m",
        [3306, :tcp] => "mysql",
        [5060, :udp] => "sip",
        [5432, :tcp] => "postgresql",
        [6379, :tcp] => "redis",
        [8443, :tcp] => "https-alt",
        [27017, :tcp] => "mongodb"
      }.freeze
      SERVICE_FAMILY_ALIASES = {
        "null" => { probe_names: ["NULL"], services: [] },
        "genericlines" => { probe_names: ["GenericLines"], services: [] },
        "httpoptions" => { probe_names: ["HTTPOptions"], services: ["http"] },
        "rtsprequest" => { probe_names: ["RTSPRequest"], services: ["rtsp"] },
        "sslsessionreq" => { probe_names: ["SSLSessionReq"], services: ["ssl", "https"] },
        "sshsessionreq" => { probe_names: [], services: ["ssh"] },
        "smtprequest" => { probe_names: [], services: ["smtp"] },
        "ftprequest" => { probe_names: [], services: ["ftp"] },
        "mssqlquery" => { probe_names: ["Sqlping"], services: ["ms-sql-s"] },
        "mysqlrequest" => { probe_names: [], services: ["mysql", "mysqlx"] },
        "postgresrequest" => { probe_names: [], services: ["postgresql"] },
        "redisrequest" => { probe_names: ["redis-server"], services: ["redis"] },
        "mongodbrequest" => { probe_names: ["mongodb"], services: ["mongodb"] },
        "dnsquery" => { probe_names: ["DNSVersionBindReq", "DNSVersionBindReqTCP", "DNSStatusRequest", "DNSStatusRequestTCP", "DNS-SD", "DNS-SD-TCP", "DNS_SD_QU"], services: ["domain", "mdns"] },
        "sipoptions" => { probe_names: ["SIPOptions"], services: ["sip"] }
      }.freeze

      class << self
        private

        def load_services
          return fallback_services unless File.file?(SERVICES_PATH)

          top_ports = []
          lookup = {}

          File.foreach(SERVICES_PATH) do |line|
            next if line.start_with?("#")

            parts = line.split
            next if parts.length < 2

            service = parts[0]
            port_proto = parts[1]
            port_string, proto_string = port_proto.split("/", 2)
            next unless port_string && proto_string

            frequency = parts[2].to_f
            entry = {
              port: port_string.to_i,
              proto: proto_string.downcase.to_sym,
              service: service,
              frequency: frequency
            }
            lookup[[entry[:port], entry[:proto]]] = service
            top_ports << entry
          end

          [top_ports.sort_by { |entry| [-entry[:frequency], entry[:port], entry[:proto].to_s] }.first(1000).freeze, lookup.freeze]
        end

        def load_probes
          return fallback_probes unless File.file?(PROBES_PATH)

          probes = []
          current = nil

          File.foreach(PROBES_PATH, mode: "rb") do |raw_line|
            line = raw_line.sub(/\r?\n\z/, "").force_encoding(Encoding::BINARY)
            next if line.empty? || line.start_with?("#")

            if line.start_with?("Probe ")
              probes << current if current
              current = parse_probe_header(line)
            elsif line.start_with?("ports ")
              current[:ports] = expand_ports(line.delete_prefix("ports ").strip)
            elsif line.start_with?("sslports ")
              current[:ssl_ports] = expand_ports(line.delete_prefix("sslports ").strip)
            elsif line.start_with?("rarity ")
              current[:rarity] = line.delete_prefix("rarity ").to_i
            elsif line.start_with?("totalwaitms ")
              current[:wait_ms] = line.delete_prefix("totalwaitms ").to_i
            elsif line.start_with?("match ")
              current[:matches] << parse_match_line(line, soft: false)
            elsif line.start_with?("softmatch ")
              current[:softmatches] << parse_match_line(line, soft: true)
            end
          end

          probes << current if current
          probes.map { |entry| Probe.new(**entry) }.freeze
        end

        def parse_probe_header(line)
          _, proto, name, quoted = line.split(/\s+/, 4)
          _, payload, = extract_delimited(quoted.delete_prefix("q"))
          {
            name: name,
            proto: proto.downcase.to_sym,
            probe_str: decode_escapes(payload),
            rarity: 5,
            wait_ms: 5000,
            ports: [],
            ssl_ports: [],
            matches: [],
            softmatches: []
          }
        end

        def parse_match_line(line, soft:)
          keyword, service, matcher = line.split(/\s+/, 3)
          raw_pattern = matcher.delete_prefix("m")
          pattern_source, remainder = extract_delimited(raw_pattern)
          flags = remainder.to_s[/\A([a-z]*)/, 1].to_s
          metadata = remainder.to_s.sub(/\A[a-z]*\s*/, "")
          {
            soft: soft || keyword == "softmatch",
            service: service,
            pattern_source: pattern_source,
            pattern_flags: flags,
            metadata: parse_metadata(metadata)
          }
        end

        def parse_metadata(metadata)
          {
            product: capture_token(metadata, "p"),
            version: capture_token(metadata, "v"),
            extra: capture_token(metadata, "i"),
            hostname: capture_token(metadata, "h"),
            os: capture_token(metadata, "o"),
            device: capture_token(metadata, "d"),
            cpes: metadata.scan(%r{cpe:/((?:\\.|[^/])*)/}).flatten
          }
        end

        def capture_token(text, key)
          text[/#{Regexp.escape(key)}\/((?:\\.|[^\/])*)\//, 1]
        end

        def extract_delimited(text)
          delimiter = text[0]
          buffer = +""
          escaped = false
          index = 1

          while index < text.length
            char = text[index]
            if escaped
              buffer << char
              escaped = false
            elsif char == "\\"
              buffer << char
              escaped = true
            elsif char == delimiter
              return [delimiter, buffer, text[(index + 1)..]]
            else
              buffer << char
            end
            index += 1
          end

          [delimiter, buffer, nil]
        end

        def decode_escapes(text)
          output = +""
          index = 0

          while index < text.length
            char = text[index]
            if char != "\\"
              output << char
              index += 1
              next
            end

            token = text[index + 1]
            case token
            when "r" then output << "\r"
            when "n" then output << "\n"
            when "t" then output << "\t"
            when "0" then output << "\0"
            when "\\" then output << "\\"
            when "x"
              output << text[(index + 2), 2].to_i(16).chr(Encoding::BINARY)
              index += 2
            else
              output << token.to_s
            end
            index += 2
          end

          output.force_encoding(Encoding::BINARY)
        end

        def expand_ports(spec)
          spec.split(",").flat_map do |segment|
            if segment.include?("-")
              first_port, last_port = segment.split("-", 2).map(&:to_i)
              (first_port..last_port).to_a
            else
              segment.to_i
            end
          end.uniq
        end

        def fallback_services
          top_ports = (1..1000).map do |port|
            {
              port: port,
              proto: :tcp,
              service: FALLBACK_SERVICE_NAMES.fetch(port, "unknown"),
              frequency: (1001 - port).to_f
            }
          end
          lookup = top_ports.each_with_object({}) do |entry, memo|
            memo[[entry[:port], entry[:proto]]] = entry[:service]
          end
          FALLBACK_SERVICE_LOOKUP_EXTRAS.each do |key, value|
            lookup[key] = value
          end
          [top_ports.freeze, lookup.freeze]
        end

        def fallback_probes
          [
            fallback_probe("NULL", :tcp, "", matches: [], softmatches: []),
            fallback_probe("GenericLines", :tcp, "\r\n", ports: [21, 22, 23, 25, 80, 110, 143], matches: [], softmatches: []),
            fallback_probe("HTTPOptions", :tcp, "OPTIONS / HTTP/1.0\r\n\r\n", ports: [80, 8080, 8000], ssl_ports: [443, 8443], matches: [match_entry("http", "^HTTP/1\\.[01] 200", metadata: { product: "Generic HTTP", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("RTSPRequest", :tcp, "OPTIONS * RTSP/1.0\r\n\r\n", ports: [554], matches: [match_entry("rtsp", "^RTSP/", metadata: { product: "Generic RTSP", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("SSLSessionReq", :tcp, "", ports: [], ssl_ports: [443, 8443], matches: [], softmatches: [match_entry("ssl", "a^", metadata: { product: nil, version: nil, extra: nil, cpes: [] })]),
            fallback_probe("SSHSessionReq", :tcp, "SSH-2.0-ASRFacet-Rb\r\n", ports: [22], matches: [match_entry("ssh", "^SSH-", metadata: { product: "Generic SSH", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("SMTPRequest", :tcp, "EHLO asrfacet-rb.local\r\n", ports: [25, 465, 587], matches: [match_entry("smtp", "^220", metadata: { product: "Generic SMTP", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("FTPRequest", :tcp, "QUIT\r\n", ports: [21], matches: [match_entry("ftp", "^220", metadata: { product: "Generic FTP", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("Sqlping", :udp, "\x02".b, ports: [1434], matches: [match_entry("ms-sql-s", ".", flags: "s", metadata: { product: "Microsoft SQL Server", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("MySQLRequest", :tcp, "\n".b, ports: [3306], matches: [match_entry("mysql", ".", flags: "s", metadata: { product: "MySQL", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("PostgresRequest", :tcp, "\x00\x00\x00\x08\x04\xd2\x16/".b, ports: [5432], matches: [match_entry("postgresql", ".", flags: "s", metadata: { product: "PostgreSQL", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("redis-server", :tcp, "INFO\r\n", ports: [6379], matches: [match_entry("redis", ".", flags: "s", metadata: { product: "Redis", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("mongodb", :tcp, "\x3a\x00\x00\x00".b, ports: [27_017], matches: [match_entry("mongodb", ".", flags: "s", metadata: { product: "MongoDB", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("DNSVersionBindReq", :udp, "\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03".b, ports: [53], matches: [match_entry("domain", ".", flags: "s", metadata: { product: "DNS", version: nil, extra: nil, cpes: [] })]),
            fallback_probe("SIPOptions", :udp, "OPTIONS sip:asrfacet-rb SIP/2.0\r\n\r\n", ports: [5060], matches: [match_entry("sip", "SIP/", metadata: { product: "SIP", version: nil, extra: nil, cpes: [] })])
          ].freeze
        end

        def fallback_probe(name, proto, probe_str, ports: [], ssl_ports: [], matches: nil, softmatches: nil, rarity: 5, wait_ms: 5000)
          Probe.new(
            name: name,
            proto: proto,
            probe_str: probe_str,
            rarity: rarity,
            wait_ms: wait_ms,
            ports: ports,
            ssl_ports: ssl_ports,
            matches: matches || [],
            softmatches: softmatches || []
          )
        end

        def match_entry(service, pattern_source, flags: "", metadata: {})
          {
            soft: false,
            service: service,
            pattern_source: pattern_source,
            pattern_flags: flags,
            metadata: {
              product: metadata[:product],
              version: metadata[:version],
              extra: metadata[:extra],
              hostname: metadata[:hostname],
              os: metadata[:os],
              device: metadata[:device],
              cpes: Array(metadata[:cpes])
            }
          }
        end
      end

      TOP_PORTS, SERVICE_LOOKUP = send(:load_services)
      PROBES = send(:load_probes)

      def probes_for(port, proto)
        normalized_proto = proto.to_sym
        matching, fallback = PROBES.select { |entry| entry.proto == normalized_proto }.partition { |entry| entry.matches_port?(port) || entry.null_probe? }
        matching + fallback
      end

      def service_for(port, proto)
        SERVICE_LOOKUP[[port.to_i, proto.to_sym]] || "unknown"
      end

      def top_ports(count)
        TOP_PORTS.first(count.to_i)
      end

      def probes_for_service(service, proto: nil)
        family = SERVICE_FAMILY_ALIASES.fetch(service.to_s.strip.downcase, {
          probe_names: [service.to_s],
          services: [service.to_s.downcase]
        })
        PROBES.select do |probe|
          next false if proto && probe.proto != proto.to_sym

          family[:probe_names].include?(probe.name) || service_match?(probe, family[:services])
        end
      end

      def supports_service?(service, proto: nil)
        !probes_for_service(service, proto: proto).empty?
      end

      private

      def service_match?(probe, services)
        return false if services.empty?

        all_services = probe.matches.map { |entry| entry[:service] } + probe.softmatches.map { |entry| entry[:service] }
        services.any? { |service| all_services.include?(service) }
      end
    end
  end
end
