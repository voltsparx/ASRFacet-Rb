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
require "pastel"
require "time"

module ASRFacet
  module Scanner
    class TerminalOutput
      def initialize(verbosity: 0, scan_mode: :auto, pastel: Pastel.new, stream: $stdout)
        @verbosity = verbosity.to_i
        @scan_mode = scan_mode.to_sym
        @pastel = pastel
        @stream = stream
      end

      def print_banner(target, scan_type, timing, mode, flags)
        write(header("=" * 64))
        write(header("ASRFacet-Rb v#{ASRFacet::VERSION} | Target: #{target}"))
        write(header("Mode: #{mode_label(mode)} | Scan: #{scan_type} | Timing: T#{timing.level} #{timing.name.capitalize}"))
        write(header("Flags: #{Array(flags).join(' ')}"))
        write(header("Started: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"))
        write(header("=" * 64))
      end

      def print_host_up(host, rtt)
        write(success("[UP]   #{host}  rtt: #{format('%.2f', rtt.to_f)}ms"))
      end

      def print_host_down(host)
        write(muted("[DOWN] #{host}  no response"))
      end

      def print_port_discovered(_host, port, proto, state, service: nil, version: nil)
        return unless visible_state?(state)

        label = case state.to_sym
                when :open then success("[OPEN]        ")
                when :open_filtered then warning("[OPEN|FILTER] ")
                when :filtered then warning("[FILTERED]    ")
                when :closed then muted("[CLOSED]      ")
                else muted("[UNKNOWN]     ")
                end
        write("#{label} #{format('%<port>d/%<proto>s', port: port, proto: proto).ljust(8)} #{service.to_s.ljust(10)} #{version}".rstrip)
      end

      def print_version_found(_host, port, service, version, info: nil, cpe: nil)
        write(success("[VERSION] #{port}/tcp  #{service}  #{[version, info].compact.join(' ')}".rstrip))
        write(muted("          CPE: #{cpe}")) unless cpe.to_s.empty?
      end

      def print_os_guess(host, os_guess)
        return if os_guess.nil? || os_guess.empty?

        write(info("[OS] #{host}  #{os_guess[:os]} (#{os_guess[:accuracy]}%)"))
        write(muted("     Vendor: #{os_guess[:vendor]} | Family: #{os_guess[:family]} | Type: #{os_guess[:device_type] || os_guess[:type]}"))
      end

      def print_source_found(source_name, count)
        write(info("[SOURCE] #{source_name}  #{count} subdomains"))
      end

      def print_subdomain_found(subdomain, ip: nil, source: nil)
        parts = ["[SUB] #{subdomain}"]
        parts << ip.to_s unless ip.to_s.empty?
        parts << "via #{source}" unless source.to_s.empty?
        write(info(parts.join("  ")))
      end

      def print_dns_record(fqdn, type, value)
        write(info("[DNS] #{fqdn}  #{type.to_s.upcase}  #{value}"))
      end

      def print_cert_found(fqdn, cn, sans, expiry, issuer)
        write(info("[CERT] #{fqdn}"))
        write(muted("       CN: #{cn} | Issuer: #{issuer}"))
        write(muted("       SANs: #{Array(sans).join(', ')}"))
        write(muted("       Expires: #{expiry}"))
      end

      def print_stage_start(stage_num, stage_name, total_stages)
        write(section("-- Stage #{stage_num}/#{total_stages}: #{stage_name} " + "-" * 40))
      end

      def print_progress(current, total, label: "")
        percent = total.to_i <= 0 ? 0 : ((current.to_f / total.to_f) * 100).round
        filled = [[(percent / 4.0).round, 25].min, 0].max
        bar = "[" + (">" * filled).ljust(25) + "]"
        write(muted("#{bar} #{percent}%  #{current}/#{total} #{label}".rstrip))
      end

      def print_scan_complete(scan_result, enum_result: nil)
        render_header(scan_result, enum_result)
        render_host_summary(scan_result)
        render_open_ports(scan_result)
        render_os_detection(scan_result)
        render_service_details(scan_result)
        render_redteam_findings(scan_result)
        render_enum_sections(enum_result)
        render_attack_surface(scan_result, enum_result)
        render_footer(scan_result, enum_result)
      end

      private

      def render_header(scan_result, enum_result)
        target = Array(scan_result&.targets).first || enum_result.dig(:meta, :target) || "target"
        duration = scan_result&.elapsed.to_f
        timing = scan_result&.timing
        write(section("=" * 60))
        write(header("SCAN COMPLETE - #{target}"))
        write(header("Duration: #{format_duration(duration)} | Timing: #{timing ? "T#{timing.level} #{timing.name.capitalize}" : 'n/a'} | Mode: #{scan_mode_label(scan_result, enum_result)}"))
        write(section("=" * 60))
      end

      def render_host_summary(scan_result)
        return if scan_result.nil?

        total = Array(scan_result.host_results).count
        up = scan_result.total_hosts_up
        down = total - up
        write(header("Hosts scanned: #{total} | Up: #{up} | Down: #{down}"))
      end

      def render_open_ports(scan_result)
        return if scan_result.nil?

        rows = Array(scan_result.host_results).flat_map do |host|
          Array(host.ports).select { |entry| %i[open open_filtered].include?(entry.state) }.map do |entry|
            [format_port(entry), state_label(entry.state), entry.service.to_s, [entry.version, entry.extra].compact.join(" ").strip]
          end
        end
        return if rows.empty?

        write(section("OPEN PORTS"))
        write(table([%w[PORT STATE SERVICE VERSION], *rows]))
        closed_count = Array(scan_result.host_results).sum { |host| host.closed_ports.count }
        write(muted("Not shown: #{closed_count} closed ports (use -v to display)")) if closed_count.positive?
      end

      def render_os_detection(scan_result)
        return if scan_result.nil?

        Array(scan_result.host_results).each do |host|
          guesses = Array(host.os_guesses)
          next if guesses.empty? && host.os.to_s.empty?

          write(section("OS Detection - #{host.host}:"))
          guesses = [{ os: host.os, accuracy: host.os_accuracy, cpe: host.os_cpe, vendor: host.os_vendor, family: host.os_family, device_type: "general purpose" }] if guesses.empty?
          guesses.each_with_index do |guess, index|
            line = "#{index + 1}. #{guess[:os].to_s.ljust(22)} #{guess[:accuracy]}%   #{guess[:device_type] || guess[:type]} | #{guess[:family]}"
            write(info("  #{line}"))
            write(muted("     CPE: #{guess[:cpe]}")) unless guess[:cpe].to_s.empty?
          end
        end
      end

      def render_service_details(scan_result)
        return if scan_result.nil?

        details = Array(scan_result.host_results).flat_map(&:open_ports)
        return if details.empty?

        write(section("SERVICE DETAILS"))
        details.each do |entry|
          write(header("+-- #{format_port(entry)} - #{entry.service.to_s.upcase} " + "-" * 38))
          write("Service : #{entry.service}")
          write("Version : #{entry.version}") unless entry.version.to_s.empty?
          write("Extra   : #{entry.extra}") unless entry.extra.to_s.empty?
          write("CPE     : #{entry.cpe}") unless entry.cpe.to_s.empty?
          write("Banner  : #{trim(entry.banner)}") unless entry.banner.to_s.empty?
          write(muted("+" + ("-" * 58)))
        end
      end

      def render_redteam_findings(scan_result)
        return if scan_result.nil?

        groups = Array(scan_result.host_results).flat_map(&:open_ports).select { |entry| Array(entry.redteam_hints).any? }
        return if groups.empty?

        write(critical("RED TEAM FINDINGS"))
        groups.each do |entry|
          write(header("-> #{format_port(entry)} - #{entry.service} #{entry.version}".strip))
          write(section("-" * 56))
          Array(entry.redteam_hints).each do |hint|
            severity = severity_label(hint.severity)
            write("#{severity} #{hint.cve ? "#{hint.cve} - " : ''}#{hint.title}")
            write(muted("           #{hint.note}")) unless hint.note.to_s.empty?
            write(muted("           ATT&CK: #{hint.technique}")) unless hint.technique.to_s.empty?
            write("           What to do: #{hint.operator_action}")
            write(muted("           Tools: #{Array(hint.tools).join(', ')}")) unless Array(hint.tools).empty?
          end
        end
      end

      def render_enum_sections(enum_result)
        return unless enum_result.is_a?(Hash)

        store = enum_result[:store]
        return unless store.respond_to?(:all)

        subdomains = Array(store.all(:subdomains))
        dns_records = Array(store.all(:dns))
        certs = Array(store.all(:certs))
        asn = Array(store.all(:asn))
        http = Array(store.all(:http_responses))

        unless subdomains.empty?
          write(section("Discovered Subdomains (#{subdomains.size}):"))
          subdomains.first(25).each do |entry|
            label = entry.to_s
            note = interesting_subdomain_note(label)
            write("#{label}#{note.empty? ? '' : "  #{note}"}")
          end
        end

        unless dns_records.empty?
          write(section("DNS Records:"))
          dns_records.first(25).each do |entry|
            row = entry.respond_to?(:to_h) ? entry.to_h : entry
            write("#{row[:host]}  #{row[:type].to_s.upcase}  #{row[:value]}")
          end
        end

        unless certs.empty?
          write(section("TLS Certificates:"))
          certs.first(10).each do |entry|
            row = entry.respond_to?(:to_h) ? entry.to_h : entry
            write("#{row[:host] || row[:domain]}:#{row[:port] || 443}")
            write("  CN      : #{row[:cn] || row[:common_name]}")
            write("  Issuer  : #{row[:issuer]}")
            write("  SANs    : #{Array(row[:sans]).join(', ')}")
          end
        end

        unless asn.empty?
          write(section("IP and Network Intelligence:"))
          asn.first(15).each do |entry|
            row = entry.respond_to?(:to_h) ? entry.to_h : entry
            write("#{row[:ip]}")
            write("  ASN     : #{row[:asn]} - #{row[:description] || row[:name]}")
            write("  Netblock: #{row[:netblock]}") unless row[:netblock].to_s.empty?
            write("  Country : #{row[:country]}") unless row[:country].to_s.empty?
          end
        end

        unless http.empty?
          write(section("Detected Technologies:"))
          http.first(15).each do |entry|
            row = entry.respond_to?(:to_h) ? entry.to_h : entry
            write("#{row[:host]} -> #{Array(row[:technologies]).join(', ')}")
          end
        end
      end

      def render_attack_surface(scan_result, enum_result)
        store = enum_result.is_a?(Hash) ? enum_result[:store] : nil
        subdomains = store.respond_to?(:all) ? Array(store.all(:subdomains)).size : 0
        ips = store.respond_to?(:all) ? Array(store.all(:ips)).size : 0
        certs = store.respond_to?(:all) ? Array(store.all(:certs)).size : 0
        tech = store.respond_to?(:all) ? Array(store.all(:http_responses)).sum { |entry| Array(entry[:technologies]).size } : 0
        critical_count = Array(scan_result&.host_results).flat_map(&:open_ports).flat_map(&:redteam_hints).count { |hint| hint.severity == :critical }
        high_count = Array(scan_result&.host_results).flat_map(&:open_ports).flat_map(&:redteam_hints).count { |hint| hint.severity == :high }

        write(section("ATTACK SURFACE MAP"))
        write("Subdomains: #{subdomains} | Open Ports: #{scan_result&.total_open.to_i}")
        write("IPs: #{ips} | Filtered: #{scan_result&.total_filtered.to_i}")
        write("Certs: #{certs} | Technologies: #{tech}")
        write("Critical Findings: #{critical_count} | High Findings: #{high_count}")

        priorities = Array(scan_result&.host_results).flat_map(&:open_ports).sort_by do |entry|
          best = Array(entry.redteam_hints).map { |hint| severity_rank(hint.severity) }.min || 9
          [best, entry.port]
        end.first(5)
        unless priorities.empty?
          write(section("PRIORITY TARGETS:"))
          priorities.each_with_index do |entry, index|
            top_hint = Array(entry.redteam_hints).min_by { |hint| severity_rank(hint.severity) }
            next if top_hint.nil?

            write("[#{index + 1}] #{top_hint.severity.to_s.upcase.ljust(8)} #{format_port(entry)} #{entry.service} - #{top_hint.title}")
          end
        end

        suggestions = next_actions(scan_result, enum_result)
        unless suggestions.empty?
          write(section("SUGGESTED NEXT ACTIONS:"))
          suggestions.each_with_index do |line, index|
            write("#{index + 1}. #{line}")
          end
        end
      end

      def render_footer(_scan_result, enum_result)
        workspace = enum_result.is_a?(Hash) ? (enum_result.dig(:meta, :workspace) || enum_result.dig(:meta, :target)) : nil
        write(section("=" * 60))
        write(header("ASRFacet-Rb v#{ASRFacet::VERSION} | For authorized engagements only"))
        write(header("Session: #{workspace}")) unless workspace.to_s.empty?
        write(section("=" * 60))
      end

      def visible_state?(state)
        case state.to_sym
        when :open, :open_filtered then true
        when :filtered then @verbosity >= 1
        when :closed then @verbosity >= 2
        else @verbosity >= 3
        end
      end

      def table(rows)
        widths = []
        rows.each do |row|
          row.each_with_index do |value, index|
            widths[index] = [widths[index].to_i, value.to_s.length].max
          end
        end

        rows.each_with_object([]) do |row, output|
          next if row.all? { |entry| entry.to_s.strip.empty? }

          line = row.each_with_index.map { |entry, index| entry.to_s.ljust(widths[index]) }.join(" ")
          output << line.rstrip
        end.join("\n")
      end

      def interesting_subdomain_note(name)
        return warning("[PRIVATE IP - INTERNAL]") if private_name?(name)
        return warning("[INTERESTING - VPN]") if name.match?(/\b(vpn|remote|access)\b/i)
        return warning("[INTERESTING]") if name.match?(/\b(dev|stage|staging|test|admin|internal|corp|backup|bak|old)\b/i)

        ""
      end

      def private_name?(name)
        IPAddr.new(name)
        IPAddr.new(name).private?
      rescue IPAddr::InvalidAddressError
        false
      end

      def next_actions(scan_result, enum_result)
        target = enum_result.is_a?(Hash) ? enum_result.dig(:meta, :target) : nil
        target ||= Array(scan_result&.targets).first || "target"
        actions = []
        Array(scan_result&.host_results).flat_map(&:open_ports).each do |port|
          case port.port
          when 3306 then actions << "mysql -h #{Array(scan_result.targets).first} -u root"
          when 22 then actions << "hydra -L users.txt -P passwords.txt ssh://#{Array(scan_result.targets).first}"
          when 80, 443 then actions << "curl -I http://#{target}"
          end
        end
        actions << "asrfacet-rb enum #{target} --active --brute" if actions.none? { |line| line.include?("enum") }
        actions << "asrfacet-rb report #{target} --format html" unless actions.any? { |line| line.include?("report") }
        actions.uniq.first(5)
      end

      def scan_mode_label(scan_result, enum_result)
        return scan_result.scan_mode.to_s.tr("_", "+").split("+").map(&:capitalize).join("+") if scan_result&.scan_mode

        mode_label(enum_result.dig(:meta, :mode) || @scan_mode)
      end

      def mode_label(mode)
        mode.to_s.tr("_", "+").split("+").map(&:capitalize).join("+")
      end

      def state_label(state)
        state.to_s.tr("_", "|")
      end

      def severity_label(severity)
        label = "[#{severity.to_s.upcase}]"
        case severity.to_sym
        when :critical then critical(label)
        when :high then danger(label)
        when :medium then warning(label)
        when :low then info(label)
        else muted(label)
        end
      end

      def severity_rank(severity)
        { critical: 0, high: 1, medium: 2, low: 3, info: 4 }.fetch(severity.to_sym, 9)
      end

      def header(text)
        @pastel.bold.white(text)
      end

      def section(text)
        @pastel.blue(text)
      end

      def success(text)
        @pastel.green(text)
      end

      def warning(text)
        @pastel.yellow(text)
      end

      def danger(text)
        @pastel.red(text)
      end

      def critical(text)
        @pastel.bold.red(text)
      end

      def info(text)
        @pastel.cyan(text)
      end

      def muted(text)
        @pastel.dim(text)
      end

      def format_port(entry)
        "#{entry.port}/#{entry.proto}"
      end

      def format_duration(seconds)
        total = seconds.to_i
        mins = total / 60
        secs = total % 60
        return "#{secs}s" if mins.zero?

        "#{mins}m #{secs}s"
      end

      def trim(value, max = 120)
        text = value.to_s.gsub(/\s+/, " ").strip
        text.length > max ? "#{text[0, max - 3]}..." : text
      end

      def write(text)
        @stream.puts(text)
      end
    end
  end
end
