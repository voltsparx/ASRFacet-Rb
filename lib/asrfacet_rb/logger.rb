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
require "thread"

module ASRFacet
  class Logger
    def initialize(stream = $stdout)
      @stream = stream
      @mutex = Mutex.new
      @pastel = Pastel.new
    rescue StandardError
      @stream = $stdout
      @mutex = Mutex.new
      @pastel = Pastel.new
    end

    def info(message)
      write("[*] #{message}", ASRFacet::Colors.terminal(:primary))
    rescue StandardError
      nil
    end

    def warn(message)
      write("[!] #{message}", ASRFacet::Colors.terminal(:warning))
    rescue StandardError
      nil
    end

    def error(message)
      write("[-] #{message}", ASRFacet::Colors.terminal(:danger))
    rescue StandardError
      nil
    end

    def success(message)
      write("[+] #{message}", ASRFacet::Colors.terminal(:success))
    rescue StandardError
      nil
    end

    private

    def write(message, color)
      @mutex.synchronize do
        @stream.puts(@pastel.decorate(message.to_s, *Array(color)))
        @stream.flush
      end
    rescue StandardError
      nil
    end
  end
end
