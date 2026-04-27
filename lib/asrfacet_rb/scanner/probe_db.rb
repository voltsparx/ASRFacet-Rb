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
      Probe = Struct.new(
        :name, :proto, :probe_str, :rarity, :wait_ms,
        :ports, :ssl_ports, :matches, :softmatches,
        keyword_init: true
      ) do
        def matches_port?(port)
          ports.include?(port.to_i) || ssl_ports.include?(port.to_i)
        end

        def null_probe?
          name == "NULL"
        end
      end

      DATA_DIR = File.expand_path("../../../data", __dir__)
      PROBES_PATH = File.join(DATA_DIR, "service-probes.db")
      SERVICES_PATH = File.join(DATA_DIR, "service-ports.db")
      DEFAULT_PROBES_PATHS = [
        PROBES_PATH,
        "/usr/share/asrfacet-rb/service-probes.db",
        "/usr/local/share/asrfacet-rb/service-probes.db"
      ].freeze
      DEFAULT_SERVICES_PATHS = [
        SERVICES_PATH,
        "/usr/share/asrfacet-rb/service-ports.db",
        "/usr/local/share/asrfacet-rb/service-ports.db"
      ].freeze

      FALLBACK_TOP_PORTS = (1..1000).map do |port|
        {
          port: port,
          proto: :tcp,
          service: {
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
            161 => "snmp",
            389 => "ldap",
            443 => "https",
            445 => "microsoft-ds",
            587 => "submission",
            993 => "imaps",
            995 => "pop3s"
          }.fetch(port, "unknown"),
          frequency: (1001 - port).to_f
        }
      end.freeze

      INTENSITY_THRESHOLDS = {
        0 => 2,
        1 => 3,
        2 => 4,
        3 => 5,
        4 => 6,
        5 => 7,
        6 => 8,
        7 => nil,
        8 => nil,
        9 => nil
      }.freeze

      PROBE_NAME_ALIASES = {
        "sshsessionreq" => ["ssh", "genericlines", "null"],
        "smtprequest" => ["smtp", "genericlines", "null"],
        "ftprequest" => ["ftp", "genericlines", "null"],
        "mssqlquery" => ["mssqls", "mssqlm", "null"],
        "mysqlrequest" => ["mysql", "null"],
        "postgresrequest" => ["postgresql", "null"],
        "redisrequest" => ["redis", "redis-server", "null"],
        "mongodbrequest" => ["mongodb", "null"],
        "dnsquery" => ["domain", "dnsversionbindreq", "dnsstatusrequest", "null"],
        "sipoptions" => ["sip", "sipoptions", "null"]
      }.freeze

      class << self
        def default
          @default ||= new(warn_proc: nil)
        end

        def load_services
          instance = new(services_path: nil, warn_proc: nil)
          [instance.top_ports(1000), instance.service_lookup]
        end

        def load_probes
          new(probes_path: nil, warn_proc: nil).probes
        end
      end

      attr_reader :probes_path, :services_path, :probes, :service_lookup

      def initialize(probes_path: nil, services_path: nil, warn_proc: method(:default_warn))
        @warn_proc = warn_proc
        @probes_path = resolve_path(probes_path, ENV["ASRFACET_PROBES_PATH"], DEFAULT_PROBES_PATHS)
        @services_path = resolve_path(services_path, ENV["ASRFACET_SERVICES_PATH"], DEFAULT_SERVICES_PATHS)
        @probes = load_probes
        @top_ports = load_services
        @service_lookup = build_service_lookup(@top_ports)
      end

      def probes_for(port, proto, intensity: 5)
        threshold = rarity_threshold(intensity)
        proto = proto.to_sym
        direct, fallback = probes.select { |probe| probe.proto == proto }.partition do |probe|
          probe.matches_port?(port) || probe.null_probe?
        end
        filtered = (direct + fallback).select do |probe|
          threshold.nil? || probe.rarity.to_i <= threshold || probe.matches_port?(port)
        end
        ordered_probes(filtered.empty? ? (direct + fallback) : filtered, port)
      end

      def service_for(port, proto)
        service_lookup.fetch([port.to_i, proto.to_sym], "unknown")
      end

      def top_ports(count)
        @top_ports.first(count.to_i)
      end

      def match_banner(banner, port, proto, intensity: 5)
        filtered = probes_for(port, proto, intensity: intensity)
        hard = filtered.lazy.flat_map(&:matches).find { |entry| regex_for(entry).match?(banner.to_s) }
        return materialize_match(hard, banner, soft: false) if hard

        soft = filtered.lazy.flat_map(&:softmatches).find { |entry| regex_for(entry).match?(banner.to_s) }
        return materialize_match(soft, banner, soft: true) if soft

        nil
      end

      def probes_for_service(service, proto: nil)
        service_name = normalize_service_name(service)
        aliases = PROBE_NAME_ALIASES.fetch(service_name, [service_name])
        probes.select do |probe|
          next false if proto && probe.proto != proto.to_sym

          aliases.include?(normalize_service_name(probe.name)) ||
            Array(probe.matches).any? { |entry| aliases.include?(normalize_service_name(entry[:service])) } ||
            Array(probe.softmatches).any? { |entry| aliases.include?(normalize_service_name(entry[:service])) }
        end
      end

      def supports_service?(service, proto: nil)
        !probes_for_service(service, proto: proto).empty?
      end

      private

      def resolve_path(explicit, env_path, defaults)
        candidates = [explicit, env_path, *Array(defaults)].compact.map(&:to_s).reject(&:empty?)
        candidates.find { |path| File.file?(path) }
      end

      def load_services
        return FALLBACK_TOP_PORTS if services_path.to_s.empty?

        entries = []
        File.foreach(services_path) do |line|
          next if line.start_with?("#")

          parts = line.split
          next if parts.length < 3

          service = parts[0]
          port_string, proto_string = parts[1].split("/", 2)
          next if port_string.to_s.empty? || proto_string.to_s.empty?

          entries << {
            port: port_string.to_i,
            proto: proto_string.downcase.to_sym,
            service: service,
            frequency: parts[2].to_f
          }
        end

        entries.sort_by { |entry| [-entry[:frequency], entry[:port], entry[:proto].to_s] }.first(1000)
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError
        warn_missing("service port catalog")
        FALLBACK_TOP_PORTS
      end

      def build_service_lookup(entries)
        entries.each_with_object({}) do |entry, memo|
          memo[[entry[:port], entry[:proto]]] = entry[:service]
        end.merge(
          [53, :udp] => "domain",
          [67, :udp] => "bootps",
          [68, :udp] => "bootpc",
          [69, :udp] => "tftp",
          [123, :udp] => "ntp",
          [1434, :udp] => "ms-sql-m",
          [5060, :udp] => "sip",
          [161, :udp] => "snmp",
          [27_017, :tcp] => "mongodb"
        )
      end

      def load_probes
        return fallback_probes if probes_path.to_s.empty?

        loaded = []
        current = nil

        File.foreach(probes_path, mode: "rb") do |raw_line|
          line = raw_line.sub(/\r?\n\z/, "").force_encoding(Encoding::BINARY)
          next if line.empty? || line.start_with?("#")
          next if line.start_with?("Exclude ")
          next if line.start_with?("fallback ")
          next if line.start_with?("tcpwrappedms ")

          if line.start_with?("Probe ")
            loaded << Probe.new(**current) if current
            current = parse_probe_header(line)
          elsif current
            parse_probe_attribute(current, line)
          end
        end

        loaded << Probe.new(**current) if current
        (loaded + missing_compatibility_probes(loaded)).freeze
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError
        warn_missing("service probe catalog")
        fallback_probes
      end

      def parse_probe_header(line)
        _keyword, proto, name, payload = line.split(/\s+/, 4)
        delimiter, probe_str, = extract_delimited(payload.delete_prefix("q"))
        raise ASRFacet::ParseError, "Unsupported probe delimiter in #{name}" if delimiter.nil?

        {
          name: name,
          proto: proto.downcase.to_sym,
          probe_str: decode_escapes(probe_str),
          rarity: 5,
          wait_ms: 5000,
          ports: [],
          ssl_ports: [],
          matches: [],
          softmatches: []
        }
      end

      def parse_probe_attribute(current, line)
        case line
        when /\Aports /
          current[:ports] = expand_ports(line.delete_prefix("ports ").strip)
        when /\Asslports /
          current[:ssl_ports] = expand_ports(line.delete_prefix("sslports ").strip)
        when /\Ararity /
          current[:rarity] = line.delete_prefix("rarity ").to_i
        when /\Atotalwaitms /
          current[:wait_ms] = line.delete_prefix("totalwaitms ").to_i
        when /\Amatch /
          current[:matches] << parse_match_line(line, soft: false)
        when /\Asoftmatch /
          current[:softmatches] << parse_match_line(line, soft: true)
        end
      end

      def parse_match_line(line, soft:)
        keyword, service, matcher = line.split(/\s+/, 3)
        pattern_segment = matcher.delete_prefix("m")
        delimiter, pattern, remainder = extract_delimited(pattern_segment)
        raise ASRFacet::ParseError, "Could not parse match pattern for #{service}" if delimiter.nil?

        flags = remainder.to_s[/\A([a-z]*)/, 1].to_s
        metadata = remainder.to_s.sub(/\A[a-z]*\s*/, "")
        {
          pattern: compile_regex(pattern, flags),
          pattern_source: normalize_pattern_source(pattern),
          service: service,
          version: capture_metadata(metadata, "v"),
          info: capture_metadata(metadata, "i"),
          hostname: capture_metadata(metadata, "h"),
          os: capture_metadata(metadata, "o"),
          cpe: metadata.scan(%r{cpe:/((?:\\.|[^/])*)/}).flatten,
          product: capture_metadata(metadata, "p"),
          soft: soft || keyword == "softmatch"
        }
      end

      def capture_metadata(metadata, key)
        metadata[/#{Regexp.escape(key)}\/((?:\\.|[^\/])*)\//, 1]
      end

      def materialize_match(entry, banner, soft:)
        match = entry[:pattern].match(banner.to_s)
        info = [replace_captures(entry[:product], match), replace_captures(entry[:info], match)].compact.join(" ").strip
        {
          service: entry[:service],
          version: replace_captures(entry[:version], match),
          info: info.empty? ? nil : info,
          hostname: replace_captures(entry[:hostname], match),
          os: replace_captures(entry[:os], match),
          cpe: Array(entry[:cpe]).map { |value| replace_captures(value, match) }.first,
          soft: soft || entry[:soft],
          confidence: (soft || entry[:soft]) ? 5 : 10
        }
      end

      def replace_captures(value, match)
        return nil if value.to_s.empty?

        value.gsub(/\$(\d+)/) { match[Regexp.last_match(1).to_i].to_s }
      end

      def rarity_threshold(intensity)
        INTENSITY_THRESHOLDS.fetch([[intensity.to_i, 0].max, 9].min)
      end

      def regex_for(entry)
        entry[:pattern]
      end

      def normalize_service_name(value)
        value.to_s.downcase.gsub(/[^a-z0-9]+/, "")
      end

      def ordered_probes(probe_list, port)
        null_probes, remaining = probe_list.partition(&:null_probe?)
        exact, broader = remaining.partition { |probe| probe.matches_port?(port) }
        null_probes + exact + broader
      end

      def compile_regex(pattern, flags)
        options = 0
        options |= Regexp::IGNORECASE if flags.include?("i")
        options |= Regexp::MULTILINE if flags.include?("s")
        source = normalize_pattern_source(pattern)
        regexp = nil
        with_suppressed_regex_warnings do
          regexp = Regexp.new(source, options)
        end
        regexp
      rescue RegexpError
        Regexp.new(Regexp.escape(pattern.to_s), options)
      end

      def normalize_pattern_source(pattern)
        pattern.to_s
      end

      def missing_compatibility_probes(loaded)
        loaded_names = loaded.map { |probe| probe.name.to_s }.to_h { |name| [name, true] }
        fallback_probes.reject { |probe| loaded_names.key?(probe.name.to_s) }
      end

      def with_suppressed_regex_warnings
        warning_singleton = Warning.singleton_class
        original_warn = warning_singleton.instance_method(:warn)
        warning_singleton.define_method(:warn) do |message, *args|
          suppressed = message.include?("character class has ']' without escape") ||
            message.include?("regular expression has ']' without escape")
          return if suppressed

          original_warn.bind_call(self, message, *args)
        end
        yield
      ensure
        warning_singleton.define_method(:warn) do |message, *args|
          original_warn.bind_call(self, message, *args)
        end
      end

      def extract_delimited(text)
        delimiter = text.to_s[0]
        return [nil, nil, nil] if delimiter.to_s.empty?

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

        [nil, nil, nil]
      end

      def decode_escapes(text)
        output = +""
        index = 0
        while index < text.to_s.length
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
            output << [text[(index + 2), 2]].pack("H2")
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
        end.select { |port| port.between?(1, 65_535) }.uniq
      end

      def warn_missing(label)
        return if @warn_proc.nil?

        @warn_proc.call("Scanner probe database could not locate #{label}; using bundled fallback data.")
      end

      def default_warn(message)
        warn(message)
      end

      def fallback_probes
        [
          probe("NULL", :tcp, "", matches: []),
          probe("GenericLines", :tcp, "\r\n", ports: [21, 22, 23, 25, 80, 110, 143], matches: []),
          probe("HTTPOptions", :tcp, "OPTIONS / HTTP/1.0\r\n\r\n", ports: [80, 8080, 8000], ssl_ports: [443, 8443], matches: [fallback_match("http", "^HTTP/1\\.[01] 200")]),
          probe("RTSPRequest", :tcp, "OPTIONS * RTSP/1.0\r\n\r\n", ports: [554], matches: [fallback_match("rtsp", "^RTSP/")]),
          probe("SSLSessionReq", :tcp, "", ssl_ports: [443, 8443], softmatches: [fallback_match("ssl", ".")]),
          probe("SSHSessionReq", :tcp, "SSH-2.0-ASRFacet-Rb\r\n", ports: [22], matches: [fallback_match("ssh", "^SSH-")]),
          probe("SMTPRequest", :tcp, "EHLO asrfacet-rb.local\r\n", ports: [25, 465, 587], matches: [fallback_match("smtp", "^220")]),
          probe("FTPRequest", :tcp, "QUIT\r\n", ports: [21], matches: [fallback_match("ftp", "^220")]),
          probe("MSSQLQuery", :udp, "\x02".b, ports: [1434], matches: [fallback_match("ms-sql-s", ".")]),
          probe("MySQLRequest", :tcp, "\n".b, ports: [3306], matches: [fallback_match("mysql", ".")]),
          probe("PostgresRequest", :tcp, "\x00\x00\x00\x08\x04\xd2\x16/".b, ports: [5432], matches: [fallback_match("postgresql", ".")]),
          probe("RedisRequest", :tcp, "INFO\r\n", ports: [6379], matches: [fallback_match("redis", ".")]),
          probe("MongoDBRequest", :tcp, "\x3a\x00\x00\x00".b, ports: [27_017], matches: [fallback_match("mongodb", ".")]),
          probe("DNSQuery", :udp, "\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03".b, ports: [53], matches: [fallback_match("domain", ".")]),
          probe("SIPOptions", :udp, "OPTIONS sip:asrfacet-rb SIP/2.0\r\n\r\n", ports: [5060], matches: [fallback_match("sip", "SIP/")])
        ].freeze
      end

      def probe(name, proto, probe_str, ports: [], ssl_ports: [], matches: [], softmatches: [], rarity: 5, wait_ms: 5000)
        Probe.new(
          name: name,
          proto: proto,
          probe_str: probe_str,
          rarity: rarity,
          wait_ms: wait_ms,
          ports: ports,
          ssl_ports: ssl_ports,
          matches: matches,
          softmatches: softmatches
        )
      end

      def fallback_match(service, source)
        {
          pattern: Regexp.new(source),
          pattern_source: source,
          service: service,
          version: nil,
          info: nil,
          hostname: nil,
          os: nil,
          cpe: [],
          product: nil,
          soft: false
        }
      end
    end

    ProbeDB::TOP_PORTS = ProbeDB.default.top_ports(1000)
  end
end
