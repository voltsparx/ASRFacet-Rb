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
      write("[*] #{message}", :blue)
    rescue StandardError
      nil
    end

    def warn(message)
      write("[!] #{message}", :yellow)
    rescue StandardError
      nil
    end

    def error(message)
      write("[-] #{message}", :red)
    rescue StandardError
      nil
    end

    def success(message)
      write("[+] #{message}", :green)
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
