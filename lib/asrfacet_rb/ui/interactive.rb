# Part of ASRFacet-Rb — authorized testing only
require "tty-prompt"
require "tty-spinner"

module ASRFacet::UI
  class Interactive
    def initialize(prompt: TTY::Prompt.new)
      @prompt = prompt
    end

    def start
      ASRFacet::UI::Banner.print

      target = @prompt.ask("Target domain:") do |q|
        q.required(true)
      end
      mode = @prompt.select("Scan mode:", %w[Full Passive Ports DNS])
      port_range = nil
      if %w[Full Ports].include?(mode)
        port_choice = @prompt.select("Port range:", ["Top100", "Top1000", "Custom"])
        port_range = port_choice == "Custom" ? @prompt.ask("Custom port range:") : port_choice.downcase
      end
      output_format = @prompt.select("Output format:", %w[CLI JSON HTML]).downcase
      shodan_key = @prompt.yes?("Add a Shodan key?") ? @prompt.mask("Shodan API key:") : nil

      summary = [
        "Target: #{target}",
        "Mode: #{mode}",
        "Ports: #{port_range || 'n/a'}",
        "Format: #{output_format}",
        "Shodan: #{shodan_key.to_s.empty? ? 'no' : 'yes'}"
      ].join(" | ")
      return nil unless @prompt.yes?("Run scan? #{summary}")

      store = run_with_spinners(target, mode, port_range, shodan_key)
      render_output(store, output_format)
    rescue StandardError => e
      ASRFacet::Core::ThreadSafe.print_error(e.message)
      nil
    end

    private

    def run_with_spinners(target, mode, port_range, shodan_key)
      case mode
      when "Full"
        current_spinner = nil
        pipeline = ASRFacet::Pipeline.new(
          target,
          ports: port_range || "top100",
          api_keys: { shodan: shodan_key },
          stage_callback: lambda do |index, name|
            current_spinner&.success("Completed stage #{index - 1}") if index > 1
            current_spinner = TTY::Spinner.new("[:spinner] Stage #{index}/8 #{name}", format: :dots)
            current_spinner.auto_spin
          end
        )
        store = pipeline.run
        current_spinner&.success("Completed stage 8")
        store
      when "Passive"
        spinner = TTY::Spinner.new("[:spinner] Running passive enumeration", format: :dots)
        spinner.auto_spin
        store = ASRFacet::ResultStore.new
        result = ASRFacet::Passive::Runner.new(target, { shodan: shodan_key }).run
        store.add(:subdomains, target)
        result[:subdomains].each { |subdomain| store.add(:subdomains, subdomain) }
        result[:errors].each { |error| store.add(:passive_errors, error) }
        spinner.success("Passive enumeration complete")
        store
      when "Ports"
        spinner = TTY::Spinner.new("[:spinner] Running port scan", format: :dots)
        spinner.auto_spin
        store = ASRFacet::ResultStore.new
        ASRFacet::Engines::PortEngine.new.scan(target, port_range || "top100").each do |entry|
          store.add(:open_ports, entry)
        end
        spinner.success("Port scan complete")
        store
      else
        spinner = TTY::Spinner.new("[:spinner] Collecting DNS records", format: :dots)
        spinner.auto_spin
        store = ASRFacet::ResultStore.new
        ASRFacet::Engines::DnsEngine.new.run(target).each do |record_type, values|
          Array(values).each { |value| store.add(:dns, { host: target, type: record_type, value: value }) }
        end
        spinner.success("DNS collection complete")
        store
      end
    rescue StandardError
      ASRFacet::ResultStore.new
    end

    def render_output(store, output_format)
      formatter = case output_format
                  when "json" then ASRFacet::Output::JsonFormatter.new
                  when "html" then ASRFacet::Output::HtmlFormatter.new
                  else ASRFacet::Output::CliFormatter.new
                  end

      if output_format == "cli"
        puts(formatter.format(store))
      else
        path = File.join(Dir.pwd, "asrfacet_report.#{output_format}")
        formatter.save(store, path)
        ASRFacet::Core::ThreadSafe.print_good("Saved report to #{path}")
      end
    rescue StandardError => e
      ASRFacet::Core::ThreadSafe.print_error(e.message)
    end
  end
end
