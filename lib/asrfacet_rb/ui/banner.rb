# Part of ASRFacet-Rb — authorized testing only
module ASRFacet
  module UI
    module Banner
      BANNER = <<~ASCII.freeze
          ___   _____ _____                 __      __
         /   | / ___// ___/___ _________  / /___  / /_
        / /| | \\__ \\\\__ \\/ __ `/ ___/ _ \\/ / __ \\/ __/
       / ___ |___/ /__/ / /_/ / /  /  __/ / /_/ / /_
      /_/  |_/____/____/\\__,_/_/   \\___/_/\\____/\\__/
      ASCII

      VERSION_LINE = "ASRFacet-Rb v#{ASRFacet::VERSION}".freeze
      TAGLINE = "Attack Surface Recon — Ruby Edition".freeze
      LEGAL_LINE = "Authorized testing only.".freeze

      def self.print
        ASRFacet::Core::ThreadSafe.puts(BANNER.cyan)
        ASRFacet::Core::ThreadSafe.puts(VERSION_LINE.white)
        ASRFacet::Core::ThreadSafe.puts(TAGLINE.white)
        ASRFacet::Core::ThreadSafe.puts(LEGAL_LINE.yellow)
      rescue StandardError
        nil
      end
    end
  end
end
