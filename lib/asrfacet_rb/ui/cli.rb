# Part of ASRFacet-Rb — authorized testing only
require "thor"

module ASRFacet
  module UI
    class CLI < Thor
    class_option :output, aliases: "-o", type: :string, desc: "Output file path"
    class_option :format, aliases: "-f", type: :string, default: "cli", enum: %w[cli json html], desc: "Output format"
    class_option :verbose, aliases: "-v", type: :boolean, default: false, desc: "Verbose output"
    class_option :threads, aliases: "-t", type: :numeric, default: 100, desc: "Worker count"
    class_option :timeout, type: :numeric, default: 10, desc: "Network timeout"

    desc "scan DOMAIN", "Run a full reconnaissance pipeline"
    method_option :ports, aliases: "-p", type: :string, desc: "Port range (top100, top1000, 1-1000, 80,443)"
    method_option :passive_only, type: :boolean, default: false, desc: "Only run passive recon"
    method_option :wordlist, aliases: "-w", type: :string, desc: "Wordlist path"
    method_option :shodan_key, type: :string, desc: "Shodan API key"
    def scan(domain)
      ASRFacet::UI::Banner.print
      store = if options[:passive_only]
                passive_store(domain)
              else
                ASRFacet::Pipeline.new(domain, build_options.merge(stage_callback: method(:announce_stage))).run
              end
      output_results(store)
    rescue StandardError => e
      ASRFacet::Core::ThreadSafe.print_error(e.message)
    end

    desc "passive DOMAIN", "Run passive enumeration only"
    def passive(domain)
      ASRFacet::UI::Banner.print
      output_results(passive_store(domain))
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
      output_results(store)
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
      output_results(store)
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
        api_keys: { shodan: options[:shodan_key] }
      }
    rescue StandardError
      {}
    end

    def passive_store(domain)
      store = ASRFacet::ResultStore.new
      result = ASRFacet::Passive::Runner.new(domain, build_options[:api_keys]).run
      store.add(:subdomains, domain)
      result[:subdomains].each { |subdomain| store.add(:subdomains, subdomain) }
      result[:errors].each { |error| store.add(:passive_errors, error) }
      store
    rescue StandardError
      ASRFacet::ResultStore.new
    end

    def output_results(store)
      formatter = case options[:format].to_s.downcase
                  when "json" then ASRFacet::Output::JsonFormatter.new
                  when "html" then ASRFacet::Output::HtmlFormatter.new
                  else ASRFacet::Output::CliFormatter.new
                  end

      if options[:output].to_s.empty?
        puts(formatter.format(store))
      else
        formatter.save(store, options[:output])
        ASRFacet::Core::ThreadSafe.print_good("Saved report to #{options[:output]}")
      end
    rescue StandardError => e
      ASRFacet::Core::ThreadSafe.print_error(e.message)
    end
    end
  end
end
