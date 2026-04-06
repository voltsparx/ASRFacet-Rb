# Part of ASRFacet-Rb — authorized testing only
require "colorize"
require "thread"

module ASRFacet
  module Core
    module ThreadSafe
      @mutex = Mutex.new

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
          line = "[*] #{msg}".colorize(ASRFacet::Colors.terminal(:primary))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_good(msg)
          line = "[+] #{msg}".colorize(ASRFacet::Colors.terminal(:success))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_error(msg)
          line = "[-] #{msg}".colorize(ASRFacet::Colors.terminal(:danger))
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_warning(msg)
          line = "[!] #{msg}".colorize(ASRFacet::Colors.terminal(:warning))
          puts(line)
          line
        rescue StandardError
          nil
        end
      end
    end
  end
end
