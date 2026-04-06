# Part of ASRFacet-Rb — authorized testing only
require "socket"
require "thread"
require "time"

module ASRFacet
  module Engines
    class PortEngine
      SERVICE_PROBES = {
        21 => { probe: "", pattern: /ftp/i, service: "ftp" },
        22 => { probe: "", pattern: /ssh/i, service: "ssh" },
        23 => { probe: "", pattern: /telnet/i, service: "telnet" },
        25 => { probe: "EHLO asrfacet.local\r\n", pattern: /smtp/i, service: "smtp" },
        53 => { probe: "", pattern: /dns/i, service: "dns" },
        80 => { probe: "HEAD / HTTP/1.0\r\n\r\n", pattern: /http/i, service: "http" },
        110 => { probe: "", pattern: /pop3/i, service: "pop3" },
        143 => { probe: "", pattern: /imap/i, service: "imap" },
        443 => { probe: "HEAD / HTTP/1.0\r\n\r\n", pattern: /http|ssl|tls/i, service: "https" },
        445 => { probe: "", pattern: /smb/i, service: "smb" },
        3306 => { probe: "", pattern: /mysql/i, service: "mysql" },
        3389 => { probe: "", pattern: /rdp/i, service: "rdp" },
        5432 => { probe: "", pattern: /postgres/i, service: "postgresql" },
        6379 => { probe: "PING\r\n", pattern: /\+PONG|redis/i, service: "redis" },
        8080 => { probe: "HEAD / HTTP/1.0\r\n\r\n", pattern: /http/i, service: "http-proxy" },
        8443 => { probe: "HEAD / HTTP/1.0\r\n\r\n", pattern: /http|ssl|tls/i, service: "https-alt" },
        27017 => { probe: "", pattern: /mongo/i, service: "mongodb" }
      }.freeze

      TOP_100_PORTS = [
        1, 7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 110, 111, 119, 123, 135, 137,
        138, 139, 143, 161, 179, 199, 389, 427, 443, 444, 445, 465, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
        1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
        5060, 5061, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9000, 9001, 9090, 9100, 9200, 9418, 9999, 10000, 11211, 27017, 50070,
        50075, 50090
      ].freeze

      TOP_1000_PORTS = ((1..1000).to_a + TOP_100_PORTS).uniq.freeze

      def initialize(target = nil, options = {})
        @target = target
        @options = options || {}
      end

      def run(host = @target, ports: "top100", workers: 100)
        data = scan(host, ports, workers: workers)
        {
          engine: "port_engine",
          target: host.to_s,
          timestamp: Time.now.iso8601,
          status: data.empty? ? :partial : :success,
          data: { open_ports: data },
          errors: []
        }
      rescue StandardError => e
        { engine: "port_engine", target: host.to_s, timestamp: Time.now.iso8601, status: :failed, data: { open_ports: [] }, errors: [e.message] }
      end

      def scan_port(host, port, timeout: 1.5)
        socket = Socket.new(:INET, :STREAM, 0)
        sockaddr = Socket.sockaddr_in(port, host)

        begin
          socket.connect_nonblock(sockaddr)
          :open
        rescue IO::WaitWritable, Errno::EINPROGRESS
          writable = IO.select(nil, [socket], nil, timeout)
          return timeout_select_result(socket) unless writable

          error_code = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
          error_code.zero? ? :open : closed_or_filtered(error_code)
        rescue Errno::ECONNREFUSED
          :closed
        rescue StandardError
          :error
        end
      rescue StandardError
        :error
      ensure
        socket&.close rescue nil
      end

      def grab_banner(host, port, timeout: 3)
        socket = TCPSocket.new(host, port)
        socket.write(SERVICE_PROBES.fetch(port, {})[:probe].to_s)
        readable = IO.select([socket], nil, nil, timeout)
        return nil unless readable

        banner = socket.readpartial(1024)
        {
          port: port,
          service: detect_service(port, banner),
          banner: banner
        }
      rescue EOFError
        nil
      rescue StandardError
        nil
      ensure
        socket&.close rescue nil
      end

      def resolve_port_range(input)
        value = input.to_s.strip.downcase
        return TOP_100_PORTS if value.empty? || value == "top100"
        return TOP_1000_PORTS if value == "top1000"

        if value.match?(/\A\d+\-\d+\z/)
          first_port, last_port = value.split("-").map(&:to_i)
          return (first_port..last_port).to_a.select { |port| port.between?(1, 65_535) }
        end

        value.split(",").map(&:to_i).select { |port| port.between?(1, 65_535) }.uniq.sort
      rescue StandardError
        TOP_100_PORTS
      end

      def scan(host, ports, workers: 100)
        results = []
        mutex = Mutex.new
        pool = ASRFacet::ThreadPool.new(workers)

        resolve_port_range(ports).each do |port|
          pool.enqueue do
            state = scan_port(host, port)
            next unless state == :open

            banner_info = grab_banner(host, port)
            mutex.synchronize do
              results << {
                host: host,
                port: port,
                state: state,
                service: banner_info&.dig(:service) || detect_service(port, nil),
                banner: banner_info&.dig(:banner).to_s.strip
              }
            end
          rescue StandardError
            nil
          end
        end

        pool.wait
        results.sort_by { |entry| entry[:port] }
      rescue StandardError
        []
      end

      private

      def closed_or_filtered(error_code)
        return :filtered if [Errno::ETIMEDOUT::Errno, Errno::EHOSTUNREACH::Errno].include?(error_code)

        :closed
      rescue StandardError
        :closed
      end

      def timeout_select_result(socket)
        return :filtered unless socket.is_a?(Socket)

        error_code = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
        return :closed if error_code.zero?

        closed_or_filtered(error_code)
      rescue StandardError
        :filtered
      end

      def detect_service(port, banner)
        probe = SERVICE_PROBES[port]
        return probe[:service] if probe && banner.to_s.match?(probe[:pattern])
        return probe[:service] if probe

        "unknown"
      rescue StandardError
        "unknown"
      end
    end
  end
end
