# Part of ASRFacet-Rb — authorized testing only
require "colorize"
require "thread"

module ASRFacet
  class Logger
    def initialize(stream = $stdout)
      @stream = stream
      @mutex = Mutex.new
    rescue StandardError
      @stream = $stdout
      @mutex = Mutex.new
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
        @stream.puts(message.to_s.colorize(color))
        @stream.flush
      end
    rescue StandardError
      nil
    end
  end
end
