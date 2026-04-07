# Part of ASRFacet-Rb - authorized testing only
require "colorize"

module ASRFacet
  module UI
    module Banner
      BANNER = <<~ASCII.freeze
           ___   _______  ____             __      ___  __
          / _ | / __/ _ \\/ __/__ ________ / /_____/ _ \\/ /
         / __ |_\\ \\/ , _/ _// _ `/ __/ -_) __/___/ , _/ _ \\
        /_/ |_/___/_/|_/_/  \\_,_/\\__/\\__/\\__/   /_/|_/_/|_|
      ASCII

      VERSION_LINE = "ASRFacet-Rb v#{ASRFacet::VERSION}".freeze
      TAGLINE = "Attack Surface Recon - Ruby Edition".freeze
      LEGAL_LINE = "Authorized testing only.".freeze

      def self.print
        ASRFacet::Core::ThreadSafe.puts(BANNER.colorize(ASRFacet::Colors.terminal(:primary)))
        ASRFacet::Core::ThreadSafe.puts(VERSION_LINE.colorize(ASRFacet::Colors.terminal(:violet)))
        ASRFacet::Core::ThreadSafe.puts(TAGLINE.colorize(ASRFacet::Colors.terminal(:info)))
        ASRFacet::Core::ThreadSafe.puts(LEGAL_LINE.colorize(ASRFacet::Colors.terminal(:warning)))
      rescue StandardError
        nil
      end
    end
  end
end
