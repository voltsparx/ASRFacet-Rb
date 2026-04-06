# Part of ASRFacet-Rb — authorized testing only
require "thor"

module ASRFacet
  module UI
    class CLI < Thor
      class_option :output, aliases: "-o", type: :string, desc: "Output file path"
      class_option :format, aliases: "-f", type: :string, default: "cli", enum: %w[cli json html txt], desc: "Output format"
      class_option :verbose, aliases: "-v", type: :boolean, default: false, desc: "Verbose output"
      class_option :threads, aliases: "-t", type: :numeric, default: 100, desc: "Worker count"
      class_option :timeout, type: :numeric, default: 10, desc: "Network timeout"
      class_option :scope, type: :string, desc: "Comma-separated allowed domains or IPs"
      class_option :exclude, type: :string, desc: "Comma-separated domains or IPs to exclude"
      class_option :monitor, type: :boolean, default: false, desc: "Show changes since the last scan"
      class_option :top, type: :numeric, default: 5, desc: "Top N scored assets to print"
      class_option :memory, type: :boolean, default: false, desc: "Skip subdomains already confirmed in previous scans"

      desc "scan DOMAIN", "Run a full reconnaissance pipeline"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range (top100, top1000, 1-1000, 80,443)"
      method_option :passive_only, type: :boolean, default: false, desc: "Only run passive recon"
      method_option :wordlist, aliases: "-w", type: :string, desc: "Wordlist path"
      method_option :shodan_key, type: :string, desc: "Shodan API key"
      def scan(domain)
        ASRFacet::UI::Banner.print
        result = if options[:passive_only]
                   passive_payload(domain)
                 else
                   ASRFacet::Pipeline.new(domain, build_options.merge(stage_callback: method(:announce_stage))).run
                 end
        output_results(result, domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "passive DOMAIN", "Run passive enumeration only"
      def passive(domain)
        ASRFacet::UI::Banner.print
        output_results(passive_payload(domain), domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "ports HOST", "Run a port scan only"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range"
      def ports(host)
        ASRFacet::UI::Banner.print
        store = ASRFacet::ResultStore.new
        ASRFacet::Engines::PortEngine.new.scan(host, options[:ports] || "top100", workers: options[:threads]).each do |entry|
          store.add(:open_ports, entry)
        end
        output_results({ store: store, top_assets: [] }, host)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "dns DOMAIN", "Run DNS collection only"
      def dns(domain)
        ASRFacet::UI::Banner.print
        store = ASRFacet::ResultStore.new
        dns_result = ASRFacet::Engines::DnsEngine.new.run(domain)
        dns_result[:data].each do |record_type, values|
          next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

          Array(values).each { |value| store.add(:dns, { host: domain, type: record_type, value: value }) }
        end
        Array(dns_result[:data][:a]).each { |ip| store.add(:ips, ip) }
        Array(dns_result[:data][:aaaa]).each { |ip| store.add(:ips, ip) }
        output_results({ store: store, top_assets: [] }, domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "interactive", "Launch the guided interactive interface"
      def interactive
        ASRFacet::UI::Interactive.new.start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "version", "Print the current version"
      def version
        puts(ASRFacet::VERSION)
      rescue StandardError
        nil
      end

      private

      def announce_stage(index, name)
        return unless options[:verbose]

        ASRFacet::Core::ThreadSafe.print_status("Stage #{index}: #{name}")
      rescue StandardError
        nil
      end

      def build_options
        {
          ports: options[:ports],
          wordlist: options[:wordlist],
          threads: options[:threads],
          timeout: options[:timeout],
          crawl_depth: 2,
          crawl_pages: 100,
          api_keys: { shodan: options[:shodan_key] },
          scope: options[:scope],
          exclude: options[:exclude],
          monitor: options[:monitor],
          top: options[:top],
          memory: options[:memory]
        }
      rescue StandardError
        {}
      end

      def passive_payload(domain)
        store = ASRFacet::ResultStore.new
        result = ASRFacet::Passive::Runner.new(domain, build_options[:api_keys]).run
        store.add(:subdomains, domain)
        result[:subdomains].each { |subdomain| store.add(:subdomains, subdomain) }
        result[:errors].each { |error| store.add(:passive_errors, error) }
        { store: store, top_assets: [] }
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [] }
      end

      def output_results(result, domain)
        payload = normalize_payload(result)
        payload[:top_assets] = Array(payload[:top_assets]).first(top_limit) if formatter_key == "cli"
        formatter = formatter_for

        if options[:output].to_s.empty?
          puts(formatter.format(payload))
        else
          formatter.save(payload, options[:output])
          ASRFacet::Core::ThreadSafe.print_good("Saved report to #{options[:output]}")
        end

        print_monitoring(payload, domain) if formatter_key == "cli" && options[:monitor]
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      def normalize_payload(result)
        return { store: result, top_assets: [] } unless result.is_a?(Hash)

        payload = result.dup
        payload[:store] ||= ASRFacet::ResultStore.new
        payload
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [] }
      end

      def formatter_for
        case formatter_key
        when "json" then ASRFacet::Output::JsonFormatter.new
        when "html" then ASRFacet::Output::HtmlFormatter.new
        when "txt" then ASRFacet::Output::TxtFormatter.new
        else ASRFacet::Output::CliFormatter.new
        end
      rescue StandardError
        ASRFacet::Output::CliFormatter.new
      end

      def formatter_key
        options[:format].to_s.downcase
      rescue StandardError
        "cli"
      end

      def top_limit
        options[:top].to_i.positive? ? options[:top].to_i : 5
      rescue StandardError
        5
      end

      def print_monitoring(payload, domain)
        diff = payload[:diff]
        return if diff.nil? || diff.empty?

        tracker = ASRFacet::Output::ChangeTracker.new(domain)
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts(tracker.format_cli(diff))
      rescue StandardError
        nil
      end
    end
  end
end
