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

require "pastel"
require "shellwords"

begin
  require "readline"
rescue LoadError
  nil
end

module ASRFacet
  module UI
    class Console
      PROMPT_NAME = "asrfacet-rb".freeze
      EXIT_COMMANDS = %w[exit quit back].freeze
      COMMAND_GROUPS = {
        "Core" => {
          "help [command]" => "Show general help or detailed help for one command/topic.",
          "about" => "Show what ASRFacet-Rb is, what it includes, and where it stores data.",
          "show commands" => "List every console command in a framework-style table.",
          "show options" => "Display the most useful global flags and what they do.",
          "show workflow" => "Display the eight-stage reconnaissance pipeline.",
          "show config" => "Display the current effective framework configuration.",
          "show learning" => "Show beginner-oriented recon and scan concepts.",
          "info <topic>" => "Explain a command, flag, or workflow in more detail.",
          "man [section]" => "Read the built-in manual or a specific section.",
          "wizard" => "Launch the console-only guided scan planner.",
          "version" => "Print the installed framework version.",
          "banner" => "Redraw the ASRFacet banner.",
          "clear" => "Clear the console screen.",
          "exit" => "Leave the console shell."
        },
        "Recon" => {
          "scan <domain>" => "Run the full attack-surface reconnaissance pipeline.",
          "passive <domain>" => "Run passive source aggregation only.",
          "dns <domain>" => "Collect DNS records only.",
          "ports <host>" => "Run a focused TCP port scan.",
          "lab" => "Launch the local validation lab for safe testing.",
          "interactive" => "Launch the beginner-friendly guided workflow."
        }
      }.freeze
      CONSOLE_TOPICS = {
        "banner" => {
          summary: "Print the framework banner again inside the console.",
          usage: "banner"
        },
        "about" => {
          summary: "Print a framework overview including capabilities, operator surfaces, and storage paths.",
          usage: "about"
        },
        "clear" => {
          summary: "Clear the console screen and keep you inside the shell.",
          usage: "clear"
        },
        "show commands" => {
          summary: "Display the framework command list in a Metasploit-style table.",
          usage: "show commands"
        },
        "show options" => {
          summary: "Display the common global flags that apply to the CLI commands.",
          usage: "show options"
        },
        "show workflow" => {
          summary: "Display the framework's eight-stage pipeline and why each stage exists.",
          usage: "show workflow"
        },
        "show config" => {
          summary: "Display the currently merged configuration for threads, timeouts, output, and HTTP settings.",
          usage: "show config"
        },
        "show learning" => {
          summary: "Display beginner-friendly recon concepts and how ASRFacet-Rb applies them.",
          usage: "show learning"
        },
        "version" => {
          summary: "Print the local ASRFacet-Rb version.",
          usage: "version"
        },
        "man" => {
          summary: "Read the built-in framework manual from inside the console.",
          usage: "man [section]"
        },
        "wizard" => {
          summary: "Launch the guided planner that recommends a scan based on your goal and safety preference.",
          usage: "wizard"
        },
        "exit" => {
          summary: "Leave the console shell.",
          usage: "exit"
        }
      }.freeze

      def initialize
        @history = []
        @pastel = Pastel.new
      rescue StandardError
        @history = []
        @pastel = Pastel.new
      end

      def start
        clear_screen
        ASRFacet::UI::Banner.print
        print_welcome

        loop do
          line = read_command
          break if line.nil?

          command = line.to_s.strip
          next if command.empty?

          break if EXIT_COMMANDS.include?(command.downcase)

          handle_line(command)
        end

        ASRFacet::Core::ThreadSafe.print_good("Leaving console mode.")
        nil
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
        nil
      end

      private

      def handle_line(command)
        case command
        when "clear"
          clear_screen
        when "banner"
          ASRFacet::UI::Banner.print
        when "about"
          ASRFacet::Core::ThreadSafe.puts(ASRFacet::UI::About.plain_text)
        when "version"
          ASRFacet::Core::ThreadSafe.puts(ASRFacet::VERSION.to_s)
        when "show commands"
          render_command_table
        when "show options"
          render_options_table
        when "show workflow"
          render_manual_section("workflow")
        when "show config"
          render_config
        when "show learning"
          render_manual_section("recon_basics")
        when "console"
          ASRFacet::Core::ThreadSafe.print_warning("You are already inside the ASRFacet console.")
        when "wizard"
          run_wizard
        when "?"
          render_help
        when /\Ahelp(?:\s+(.*))?\z/i
          topic = Regexp.last_match(1)
          render_help(topic)
        when /\Aman(?:\s+(.*))?\z/i
          render_manual_section(Regexp.last_match(1))
        when /\Ainfo\s+(.+)\z/i
          render_explanation(Regexp.last_match(1))
        when /\Aexplain\s+(.+)\z/i
          render_explanation(Regexp.last_match(1))
        else
          dispatch_cli(command)
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      def dispatch_cli(command)
        argv = Shellwords.shellsplit(command)
        return nil if argv.empty?

        argv.reject! { |arg| %w[--console -C console].include?(arg) }
        ASRFacet::UI::CLI.start(argv)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
        nil
      end

      def render_help(topic = nil)
        if topic.to_s.strip.empty?
          print_help_overview
        else
          render_explanation(topic)
        end
      rescue StandardError
        nil
      end

      def render_explanation(topic)
        explanation = console_explanation(topic) || ASRFacet::UI::HelpCatalog.explain(topic)
        explanation ||= ASRFacet::UI::Manual.plain_text(topic)
        if explanation.to_s.empty?
          ASRFacet::Core::ThreadSafe.print_warning("No detailed help for `#{topic}`. Try `help` to see available topics.")
        else
          ASRFacet::Core::ThreadSafe.puts(explanation)
        end
      rescue StandardError
        nil
      end

      def print_welcome
        lines = [
          startup_line("=[", "ASRFacet-Rb v#{ASRFacet::VERSION}", :primary),
          startup_line("+ -- --=[", "Event-driven reconnaissance console ready", :info),
          startup_line("+ -- --=[", "Authorized testing only", :warning),
          startup_line("+ -- --=[", "#{COMMAND_GROUPS.values.map(&:size).sum} console commands loaded", :success),
          startup_line("+ -- --=[", "Type `help` or `show commands` to begin", :violet)
        ]
        ASRFacet::Core::ThreadSafe.puts("")
        lines.each { |line| ASRFacet::Core::ThreadSafe.puts(line) }
        ASRFacet::Core::ThreadSafe.puts("")
      rescue StandardError
        nil
      end

      def startup_line(prefix, text, tone)
        @pastel.decorate("#{prefix} #{text}", *Array(ASRFacet::Colors.terminal(tone)))
      rescue StandardError
        text.to_s
      end

      def print_help_overview
        ASRFacet::Core::ThreadSafe.puts(ASRFacet::UI::HelpCatalog.menu(executable: PROMPT_NAME))
        ASRFacet::Core::ThreadSafe.puts("")
        render_command_table
        ASRFacet::Core::ThreadSafe.puts("")
        render_options_table
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts("Try `show workflow`, `show config`, `show learning`, `man`, or `wizard` for deeper guidance.")
      rescue StandardError
        nil
      end

      def render_command_table
        rows = []
        COMMAND_GROUPS.each do |group, commands|
          commands.each do |command, description|
            rows << [group, command, description]
          end
        end
        render_ascii_table(
          ["Dispatcher", "Command", "Description"],
          rows
        )
      rescue StandardError
        rows.each do |group, command, description|
          ASRFacet::Core::ThreadSafe.puts("#{group} | #{command} | #{description}")
        end
      end

      def render_options_table
        rows = [
          ["-o, --output PATH", "Save output to a file instead of printing it."],
          ["-f, --format TYPE", "Choose cli, json, html, or txt report output."],
          ["-v, --verbose", "Print stage-by-stage status updates during a run."],
          ["-t, --threads N", "Adjust worker concurrency for threaded engines."],
          ["--timeout SEC", "Increase or decrease the network timeout."],
          ["--scope LIST", "Add additional authorized domains or IPs."],
          ["--exclude LIST", "Block domains or IPs from any active probing."],
          ["--monitor", "Print what changed since the last saved scan."],
          ["--top N", "Control how many top-ranked assets print in CLI mode."],
          ["--memory", "Skip already confirmed subdomains from prior scans."],
          ["--headless", "Render JavaScript-heavy pages in a headless browser when available."],
          ["--webhook-url URL", "Send high-severity finding alerts to Slack or Discord."],
          ["--webhook-platform NAME", "Choose slack or discord for webhook payload formatting."],
          ["--delay MS", "Apply a base delay between requests in milliseconds."],
          ["--adaptive-rate", "Back off automatically when 429 or 503 responses appear."],
          ["-C, --console", "Open the persistent ASRFacet console shell."]
        ]
        render_ascii_table(
          ["Option", "Meaning"],
          rows
        )
      rescue StandardError
        rows.each { |option, description| ASRFacet::Core::ThreadSafe.puts("#{option} | #{description}") }
      end

      def console_explanation(topic)
        normalized = topic.to_s.strip.downcase
        normalized = "show commands" if normalized == "commands"
        normalized = "show options" if normalized == "options"
        normalized = "show workflow" if normalized == "workflow"
        normalized = "show config" if normalized == "config"
        normalized = "show learning" if %w[learning recon basics].include?(normalized)
        entry = CONSOLE_TOPICS[normalized]
        return nil if entry.nil?

        [
          "Explain: #{normalized}",
          "",
          "Summary:",
          "  #{entry[:summary]}",
          "",
          "Usage:",
          "  #{entry[:usage]}"
        ].join("\n")
      rescue StandardError
        nil
      end

      def prompt
        base = @pastel.decorate("asrfrb", *Array(ASRFacet::Colors.terminal(:primary)))
        arrow = @pastel.decorate(">", *Array(ASRFacet::Colors.terminal(:warning)))
        "#{base} #{arrow} "
      rescue StandardError
        "asrfrb > "
      end

      def clear_screen
        if Gem.win_platform?
          system("cls")
        else
          print("\e[2J\e[H")
        end
        nil
      rescue StandardError
        nil
      end

      def read_command
        if defined?(Readline)
          Readline.readline(prompt, true)
        else
          ASRFacet::Core::ThreadSafe.print(prompt)
          STDIN.gets
        end
      rescue StandardError
        nil
      end

      def render_ascii_table(headers, rows)
        widths = headers.each_index.map do |index|
          ([headers[index].to_s.length] + rows.map { |row| row[index].to_s.length }).max
        end

        divider = "+" + widths.map { |width| "-" * (width + 2) }.join("+") + "+"
        header_row = "|" + headers.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"

        ASRFacet::Core::ThreadSafe.puts(divider)
        ASRFacet::Core::ThreadSafe.puts(header_row)
        ASRFacet::Core::ThreadSafe.puts(divider)
        rows.each do |row|
          line = "|" + row.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"
          ASRFacet::Core::ThreadSafe.puts(line)
        end
        ASRFacet::Core::ThreadSafe.puts(divider)
      rescue StandardError
        rows.each { |row| ASRFacet::Core::ThreadSafe.puts(row.join(" | ")) }
      end

      def render_manual_section(section = nil)
        text = ASRFacet::UI::Manual.plain_text(section)
        if text.to_s.empty?
          ASRFacet::Core::ThreadSafe.print_warning("No manual section for `#{section}`.")
        else
          ASRFacet::Core::ThreadSafe.puts(text)
        end
      rescue StandardError
        nil
      end

      def render_config
        rows = flatten_config(ASRFacet::Config.load)
        render_ascii_table(["Setting", "Value"], rows)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      def flatten_config(config, prefix = nil)
        config.each_with_object([]) do |(key, value), rows|
          full_key = [prefix, key].compact.join(".")
          if value.is_a?(Hash)
            rows.concat(flatten_config(value, full_key))
          else
            rows << [full_key, value.inspect]
          end
        end
      rescue StandardError
        []
      end

      def run_wizard
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts("Wizard mode helps you choose a scan profile and teaches what each choice means.")
        ASRFacet::Core::ThreadSafe.puts("You can press Ctrl+C to return to the console at any time.")
        ASRFacet::Core::ThreadSafe.puts("")

        target = ask_line("What domain or host are you authorized to assess?", required: true)
        goal = choose_option(
          "What is your main goal?",
          [
            "Learn the target's footprint safely",
            "Map the full web-facing attack surface",
            "Check exposed ports and services",
            "Track changes between repeated scans",
            "Build a custom guided run"
          ]
        )
        profile_name = choose_option("How aggressive should the scan be?", ASRFacet::UI::Manual::WIZARD_PROFILES.keys)
        profile = ASRFacet::UI::Manual::WIZARD_PROFILES[profile_name]
        output_format = choose_option("Which output format fits your workflow?", %w[cli html json txt])
        scope = ask_line("Additional in-scope domains or IPs? (comma-separated, optional)")
        exclude = ask_line("Anything to exclude? (comma-separated, optional)")
        shodan_key = ask_yes_no("Do you want to use a Shodan key for passive enrichment?") ? ask_line("Shodan API key:") : nil

        plan = build_wizard_plan(
          target: target,
          goal: goal,
          profile_name: profile_name,
          profile: profile,
          output_format: output_format,
          scope: scope,
          exclude: exclude,
          shodan_key: shodan_key
        )

        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts("Why this plan?")
        plan[:teaching_points].each { |line| ASRFacet::Core::ThreadSafe.puts("  - #{line}") }
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts("Recommended command:")
        ASRFacet::Core::ThreadSafe.puts("  #{Shellwords.join(plan[:command])}")
        ASRFacet::Core::ThreadSafe.puts("")

        return nil unless ask_yes_no("Run this plan now?")

        ASRFacet::UI::CLI.start(plan[:command])
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
        nil
      end

      def build_wizard_plan(target:, goal:, profile_name:, profile:, output_format:, scope:, exclude:, shodan_key:)
        mode = recommended_mode(goal, profile)
        command = ["scan", target.to_s]
        teaching_points = [
          "#{profile_name} profile: #{profile[:narrative]}",
          educational_goal(goal),
          "Output format: #{output_format} helps you consume the results in the way you described."
        ]

        case mode
        when "passive"
          command = ["passive", target.to_s]
          teaching_points << "Passive discovery uses third-party knowledge first, which is ideal for safe footprinting."
        when "ports"
          command = ["ports", target.to_s, "--ports", profile[:ports]]
          teaching_points << "Port scanning reveals reachable services, which is the foundation for deeper host and web analysis."
        when "dns"
          command = ["dns", target.to_s]
          teaching_points << "DNS is often the first pivot point because hostnames, MX records, and CNAMEs reveal structure."
        else
          command += ["--ports", profile[:ports]]
          teaching_points << "The full pipeline validates assets across DNS, services, HTTP, and findings so you get a complete attack-surface picture."
        end

        command += ["--threads", profile[:threads].to_s]
        command += ["--format", output_format]
        command << "--monitor" if goal.include?("Track changes") || profile[:monitor]
        command << "--memory" if profile[:memory]
        normalized_scope = normalize_list_argument(scope)
        normalized_exclude = normalize_list_argument(exclude)
        command += ["--scope", normalized_scope] unless normalized_scope.empty?
        command += ["--exclude", normalized_exclude] unless normalized_exclude.empty?
        command += ["--shodan-key", shodan_key] unless shodan_key.to_s.empty?

        {
          command: command,
          teaching_points: teaching_points
        }
      rescue StandardError
        { command: ["scan", target.to_s], teaching_points: [] }
      end

      def recommended_mode(goal, profile)
        return "passive" if goal.include?("footprint")
        return "ports" if goal.include?("ports")
        return "full" if goal.include?("web-facing") || goal.include?("changes")

        profile[:mode].to_s.downcase
      rescue StandardError
        "full"
      end

      def educational_goal(goal)
        case goal
        when /footprint/i
          "Goal mapping: start broad and carefully, then deepen only after you understand what assets exist."
        when /web-facing/i
          "Goal mapping: web attack surface work benefits from HTTP probing, crawling, and JavaScript endpoint analysis."
        when /ports/i
          "Goal mapping: service exposure tells you what protocols and management surfaces are reachable."
        when /changes/i
          "Goal mapping: recon memory plus monitoring helps you see what is new, removed, or changed over time."
        else
          "Goal mapping: the wizard turns your learning objective into a concrete command you can inspect and reuse."
        end
      rescue StandardError
        ""
      end

      def normalize_list_argument(value)
        value.to_s.split(",").map(&:strip).reject(&:empty?).join(",")
      rescue StandardError
        ""
      end

      def ask_line(label, required: false)
        loop do
          ASRFacet::Core::ThreadSafe.print("#{label}: ")
          value = STDIN.gets
          return "" if value.nil? && !required

          text = value.to_s.strip
          return text unless required && text.empty?

          ASRFacet::Core::ThreadSafe.print_warning("A value is required for this step.")
        end
      rescue StandardError
        ""
      end

      def choose_option(label, options)
        ASRFacet::Core::ThreadSafe.puts(label)
        Array(options).each.with_index(1) do |option, index|
          ASRFacet::Core::ThreadSafe.puts("  #{index}. #{option}")
        end

        loop do
          ASRFacet::Core::ThreadSafe.print("Choose 1-#{options.length}: ")
          input = STDIN.gets
          return options.first if input.nil?

          index = input.to_s.strip.to_i
          return options[index - 1] if index.between?(1, options.length)

          ASRFacet::Core::ThreadSafe.print_warning("Please enter a valid number from the list.")
        end
      rescue StandardError
        Array(options).first
      end

      def ask_yes_no(label)
        loop do
          ASRFacet::Core::ThreadSafe.print("#{label} [y/N]: ")
          input = STDIN.gets
          return false if input.nil?

          answer = input.to_s.strip.downcase
          return true if %w[y yes].include?(answer)
          return false if answer.empty? || %w[n no].include?(answer)

          ASRFacet::Core::ThreadSafe.print_warning("Please answer y or n.")
        end
      rescue StandardError
        false
      end
    end
  end
end
