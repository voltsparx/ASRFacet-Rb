# Part of ASRFacet-Rb — authorized testing only
require "colorize"
require "thread"

module ASRFacet::Core::ThreadSafe
  @mutex = Mutex.new

  class << self
    attr_reader :mutex

    def print(msg)
      mutex.synchronize do
        $stdout.print(msg)
        $stdout.flush
      end
    rescue StandardError
      nil
    end

    def puts(msg)
      mutex.synchronize do
        $stdout.puts(msg)
        $stdout.flush
      end
    rescue StandardError
      nil
    end

    def print_status(msg)
      output = "[*] #{msg}".blue
      puts(output)
      output
    rescue StandardError
      nil
    end

    def print_good(msg)
      output = "[+] #{msg}".green
      puts(output)
      output
    rescue StandardError
      nil
    end

    def print_error(msg)
      output = "[-] #{msg}".red
      puts(output)
      output
    rescue StandardError
      nil
    end

    def print_warning(msg)
      output = "[!] #{msg}".yellow
      puts(output)
      output
    rescue StandardError
      nil
    end
  end
end
