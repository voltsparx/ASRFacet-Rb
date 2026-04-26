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
        pastel = Pastel.new
        ASRFacet::Core::ThreadSafe.puts(pastel.decorate(BANNER, ASRFacet::Colors.terminal(:primary)))
        ASRFacet::Core::ThreadSafe.puts(pastel.decorate(VERSION_LINE, ASRFacet::Colors.terminal(:violet)))
        ASRFacet::Core::ThreadSafe.puts(pastel.decorate(TAGLINE, ASRFacet::Colors.terminal(:info)))
        ASRFacet::Core::ThreadSafe.puts(pastel.decorate(LEGAL_LINE, ASRFacet::Colors.terminal(:warning)))
      rescue ASRFacet::Error
        nil
      end
    end
  end
end
