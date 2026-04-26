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
  module Core
    module ThreadSafe
      @mutex = Mutex.new
      @pastel = Pastel.new

      class << self
        attr_reader :mutex

        def print(msg)
          mutex.synchronize do
            $stdout.print(msg.to_s)
            $stdout.flush
          end
        rescue StandardError
          nil
        end

        def puts(msg = "")
          mutex.synchronize do
            $stdout.puts(msg.to_s)
            $stdout.flush
          end
        rescue StandardError
          nil
        end

        def print_status(msg)
          line = decorate("[*] #{msg}", ASRFacet::Colors.terminal(:primary))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_good(msg)
          line = decorate("[+] #{msg}", ASRFacet::Colors.terminal(:success))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_error(msg)
          line = decorate("[-] #{msg}", ASRFacet::Colors.terminal(:danger))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_warning(msg)
          line = decorate("[!] #{msg}", ASRFacet::Colors.terminal(:warning))
          puts(line)
          line
        rescue StandardError
          nil
        end

        private

        def decorate(text, color)
          @pastel.decorate(text.to_s, *Array(color))
        end
      end
    end
  end
end
