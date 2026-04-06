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
          line = "[*] #{msg}".blue
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_good(msg)
          line = "[+] #{msg}".green
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_error(msg)
          line = "[-] #{msg}".red
          puts(line)
          line
        rescue StandardError
          nil
        end

        def print_warning(msg)
          line = "[!] #{msg}".yellow
          puts(line)
          line
        rescue StandardError
          nil
        end
      end
    end
  end
end
