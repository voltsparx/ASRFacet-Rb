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

begin
  require "tty-progressbar"
rescue LoadError
  module TTY
    class ProgressBar
      attr_accessor :format
      attr_reader :current

      def initialize(*, **)
        @current = 0
      end

      def start
        @current = 0
      end

      def advance(amount = 1)
        @current += amount
      end

      def update(**)
        nil
      end

      def finish
        @current = 100
      end
    end
  end
end

module ASRFacet
  class ProgressDashboard
    STAGES = [
      "Passive Collection",
      "DNS + Certificate",
      "Permutation + Busting",
      "Discovery Feedback",
      "Port Scanning",
      "HTTP + Crawl + JS",
      "WHOIS + ASN",
      "Findings + Monitor"
    ].freeze

    def initialize
      @pastel = Pastel.new
      @bars = {}
      @counts = Hash.new(0)
      build_bars
    end

    def start(stage_index)
      name = STAGES[stage_index]
      return nil unless name

      @bars[stage_index]&.start
      print_stage_header(stage_index, name)
    end

    def increment(stage_index, found: 0)
      @counts[stage_index] += found
      bar = @bars[stage_index]
      return nil if bar.nil?

      bar.advance(100 - bar.current) if bar.current < 100
      bar.format = current_format(stage_index)
      bar.update(found: @counts[stage_index])
    end

    def finish(stage_index)
      @bars[stage_index]&.finish
    end

    def finish_all
      @bars.each_value(&:finish)
    end

    def count(stage_index)
      @counts[stage_index]
    end

    private

    def build_bars
      STAGES.each_with_index do |name, index|
        label = @pastel.cyan(name.ljust(28))
        @bars[index] = TTY::ProgressBar.new(
          "#{label} [:bar] :percent  :found found",
          total: 100,
          width: 30,
          head: ">",
          filled: "#",
          clear: false,
          tokens: { found: 0 }
        )
      end
    end

    def current_format(stage_index)
      count = @counts[stage_index]
      name = STAGES[stage_index].ljust(28)
      "#{@pastel.cyan(name)} [:bar] :percent  #{@pastel.green(count.to_s)} found"
    end

    def print_stage_header(index, name)
      puts @pastel.bold.white("\n[Stage #{index + 1}/#{STAGES.size}] #{name}")
    end
  end
end
