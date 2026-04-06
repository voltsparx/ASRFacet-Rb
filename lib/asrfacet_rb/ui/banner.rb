# Part of ASRFacet-Rb — authorized testing only
module ASRFacet::UI::Banner
  BANNER = <<~ASCII.freeze
     ___   _____ _____            __         __
    /   | / ___// ___/___ _______/ /__  ____/ /
   / /| | \\__ \\\\__ \\/ _ `/ ___/ _  / _ \\/ __  /
  / ___ |___/ /__/ /\\_,_/_/   \\_,_/\\___/\\_,_/
 /_/  |_/____/____/
  ASCII

  VERSION_LINE = "ASRFacet-Rb v#{ASRFacet::VERSION}".freeze
  LEGAL_LINE = "Authorized testing only.".freeze

  def self.print
    ASRFacet::Core::ThreadSafe.puts(BANNER.cyan)
    ASRFacet::Core::ThreadSafe.puts(VERSION_LINE.white)
    ASRFacet::Core::ThreadSafe.puts(LEGAL_LINE.yellow)
  rescue StandardError
    nil
  end
end
