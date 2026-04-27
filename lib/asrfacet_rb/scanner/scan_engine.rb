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

require "concurrent"
require "thread"
require "time"

module ASRFacet
  module Scanner
    class ScanEngine
      SCAN_TYPES = {
        connect: ASRFacet::Scanner::ScanTypes::ConnectScan,
        syn: ASRFacet::Scanner::ScanTypes::SynScan,
        udp: ASRFacet::Scanner::ScanTypes::UdpScan,
        ack: ASRFacet::Scanner::ScanTypes::AckScan,
        fin: ASRFacet::Scanner::ScanTypes::FinScan,
        null: ASRFacet::Scanner::ScanTypes::NullScan,
        xmas: ASRFacet::Scanner::ScanTypes::XmasScan,
        window: ASRFacet::Scanner::ScanTypes::WindowScan,
        maimon: ASRFacet::Scanner::ScanTypes::MaimonScan,
        ping: ASRFacet::Scanner::ScanTypes::PingScan,
        service: ASRFacet::Scanner::ScanTypes::ServiceScan
      }.freeze

      COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080].freeze

      def initialize(scan_type:, timing:, verbosity:, version_detection:, os_detection:, version_intensity:, ports:, logger: nil, probe_db: ASRFacet::Scanner::ProbeDB.default, tcp_prober: nil, udp_prober: ASRFacet::Scanner::Probes::UDPProber.new, icmp_prober: ASRFacet::Scanner::Probes::ICMPProber.new, raw_backend: :auto, terminal: ASRFacet::Scanner::TerminalOutput.new, result_store: nil, knowledge_graph: nil, flags_used: [])
        @scan_type = scan_type.to_sym
        @timing = timing.is_a?(ASRFacet::Scanner::Timing::Template) ? timing : ASRFacet::Scanner::Timing.get(timing)
        @verbosity = verbosity.to_i
        @version_detection = version_detection || @scan_type == :service
        @os_detection = os_detection
        @ports = ports
        @logger = logger || ASRFacet::Scanner::VerboseLogger.new(level: @verbosity)
        @probe_db = probe_db
        @terminal = terminal
        @result_store = result_store
        @knowledge_graph = knowledge_graph
        @flags_used = Array(flags_used)
        tcp_prober ||= default_tcp_prober(raw_backend)
        @version_detector = ASRFacet::Scanner::VersionDetector.new(probe_db: @probe_db, intensity: version_intensity)
        @fingerprint_engine = ASRFacet::Scanner::FingerprintEngine.new(tcp_prober: tcp_prober)
        @context = ASRFacet::Scanner::ScanContext.new(
          timing: @timing,
          logger: @logger,
          terminal: @terminal,
          probe_db: @probe_db,
          tcp_prober: tcp_prober,
          udp_prober: udp_prober,
          icmp_prober: icmp_prober,
          version_detector: @version_detector,
          fingerprint_engine: @fingerprint_engine
        )
      end

      def scan(targets)
        ASRFacet::Scanner::Privilege.validate!(scan_type: @scan_type, tcp_prober: @context.tcp_prober)
        normalized_targets = Array(targets)
        port_list = parse_ports(@ports)
        result = ASRFacet::Scanner::Results::ScanResult.new(
          targets: normalized_targets,
          scan_type: @scan_type,
          scan_mode: (@scan_type == :ping ? :discovery : :active),
          timing: @timing,
          started_at: Time.now.utc,
          flags_used: @flags_used
        )

        @logger.start_scan(normalized_targets, scan_type: @scan_type, timing: @timing, ports: port_list)
        normalized_targets.each do |target|
          host_result = scan_host(target, port_list)
          result.add_host(host_result)
          persist_host(host_result)
          @logger.print_port_table(host_result)
        end

        result.finished_at = Time.now.utc
        @logger.scan_complete(result)
        @logger.print_summary(result)
        result
      end

      private

      def default_tcp_prober(raw_backend)
        raw_adapter = build_raw_adapter(raw_backend)
        ASRFacet::Scanner::Probes::TCPProber.new(raw_adapter: raw_adapter)
      end

      def build_raw_adapter(raw_backend)
        backend = raw_backend.to_s.downcase
        return nil if backend == "builtin" || backend == "none"
        return ASRFacet::Scanner::Probes::NpingRawAdapter.new if %w[auto nping].include?(backend)

        nil
      rescue StandardError
        nil
      end

      def scan_host(target, port_list)
        host_result = ASRFacet::Scanner::Results::HostResult.new(
          host: target,
          scan_delay_used: @timing.scan_delay,
          timing_level_used: @timing.level
        )
        ping_scan = ASRFacet::Scanner::ScanTypes::PingScan.new(@context)

        unless @scan_type == :ping || ping_scan.host_up?(target)
          @logger.host_down(target)
          @terminal&.print_host_down(target)
          return host_result
        end

        host_result.up = true
        @logger.host_up(target)
        @terminal&.print_host_up(target, 0.0)
        return host_result.add_port(ping_scan.probe(target)) && host_result if @scan_type == :ping

        scanner = SCAN_TYPES.fetch(@scan_type).new(@context)
        mutex = Mutex.new
        executor = executor_for(port_list.count)
        latch = Concurrent::CountDownLatch.new(port_list.count)

        port_list.each do |port|
          executor.post do
            port_result = scanner.probe(target, port)
            apply_version_detection(target, port_result) if @version_detection && port_result.open?
            port_result.redteam_hints = ASRFacet::Scanner::RedTeamHintEngine.hints_for(
              service: port_result.service,
              version: port_result.version,
              port: port_result.port,
              cpe: port_result.cpe
            ) if port_result.open?
            mutex.synchronize { host_result.add_port(port_result) }
            log_port_result(target, port_result)
          ensure
            latch.count_down
          end
        end

        latch.wait
        executor.shutdown
        executor.wait_for_termination
        apply_os_detection(target, host_result) if @os_detection
        @terminal&.print_os_guess(target, host_result.best_os) if @os_detection
        host_result
      end

      def apply_version_detection(target, port_result)
        detected = @version_detector.detect(target, port_result.port, proto: port_result.proto)
        return unless detected

        port_result.service = detected[:service] if detected[:service]
        port_result.version = detected[:version] if detected[:version]
        port_result.extra = detected[:extra_info] if detected[:extra_info]
        port_result.cpe = detected[:cpe] if detected[:cpe]
        port_result.banner = detected[:banner] if detected[:banner]
        version_label = [port_result.service, port_result.version].compact.join(" ").strip
        @logger.version_detected(target, port_result.port, version_label) unless version_label.empty?
        @terminal&.print_version_found(target, port_result.port, port_result.service, port_result.version, info: port_result.extra, cpe: port_result.cpe)
      end

      def apply_os_detection(target, host_result)
        fingerprint = @context.tcp_prober.fingerprint(host: target, timeout: @timing.max_rtt_timeout.to_f / 1000.0)
        guesses = @fingerprint_engine.classify(fingerprint || {})
        os_result = guesses.first || @fingerprint_engine.detect_os_for(target)
        host_result.os = os_result[:os]
        host_result.os_accuracy = os_result[:accuracy]
        host_result.os_cpe = os_result[:cpe]
        host_result.os_vendor = os_result[:vendor]
        host_result.os_family = os_result[:family]
        host_result.os_guesses = guesses
        @logger.os_detected(target, os_result)
      end

      def log_port_result(target, port_result)
        @terminal&.print_port_discovered(
          target,
          port_result.port,
          port_result.proto,
          port_result.state,
          service: port_result.service,
          version: [port_result.version, port_result.extra].compact.join(" ").strip
        )
        case port_result.state
        when :open then @logger.port_open(target, port_result)
        when :closed then @logger.port_closed(target, port_result)
        else @logger.port_filtered(target, port_result)
        end
      end

      def executor_for(task_count)
        max_threads = @timing.max_parallelism.zero? ? [task_count, 300].min : @timing.max_parallelism
        min_threads = @timing.min_parallelism.zero? ? 1 : @timing.min_parallelism
        Concurrent::ThreadPoolExecutor.new(
          min_threads: [min_threads, max_threads].min,
          max_threads: [max_threads, 1].max,
          max_queue: [task_count, 1].max,
          fallback_policy: :caller_runs
        )
      end

      def parse_ports(spec)
        case spec.to_s.strip.downcase
        when "", "top100"
          @probe_db.top_ports(100).map { |entry| entry[:port] }
        when "top1000"
          @probe_db.top_ports(1000).map { |entry| entry[:port] }
        when "top65535"
          (1..65_535).to_a
        when "common"
          COMMON_PORTS
        else
          spec.to_s.split(",").flat_map do |segment|
            if segment.include?("-")
              first_port, last_port = segment.split("-", 2).map(&:to_i)
              (first_port..last_port).to_a
            else
              segment.to_i
            end
          end.select { |port| port.between?(1, 65_535) }.uniq.sort
        end
      end

      def persist_host(host_result)
        return if @result_store.nil? && @knowledge_graph.nil?

        if @result_store
          @result_store.add(:ips, host_result.host)
          Array(host_result.ports).each do |port_result|
            category = case port_result.state
                       when :open then :open_ports
                       when :closed then :closed_ports
                       else :filtered_ports
                       end
            @result_store.add(category, port_result.to_h.merge(host: host_result.host))
          end
        end

        return unless @knowledge_graph

        @knowledge_graph.add_node(host_result.host, type: :ip, data: { up: host_result.up })
        Array(host_result.ports).each do |port_result|
          service_id = "#{host_result.host}:#{port_result.port}/#{port_result.proto}"
          @knowledge_graph.add_node(service_id, type: :service, data: port_result.to_h)
          @knowledge_graph.add_edge(host_result.host, service_id, relation: :runs_on)
        end
      rescue StandardError
        nil
      end
    end
  end
end
