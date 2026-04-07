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

require "digest"

module ASRFacet
  module Core
    module StringExtensions
      refine String do
        def md5
          Digest::MD5.hexdigest(self)
        rescue StandardError
          ""
        end

        def sha1
          Digest::SHA1.hexdigest(self)
        rescue StandardError
          ""
        end

        def sha256
          Digest::SHA256.hexdigest(self)
        rescue StandardError
          ""
        end

        def domain?
          match?(/\A[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\z/)
        rescue StandardError
          false
        end

        def ip?
          match?(/\A(\d{1,3}\.){3}\d{1,3}\z/) || match?(/\A[0-9a-fA-F:]+\z/)
        rescue StandardError
          false
        end

        def strip_protocol
          gsub(/\Ahttps?:\/\//, "").chomp("/")
        rescue StandardError
          to_s
        end

        def to_hostname
          strip_protocol.split("/").first.to_s.split(":").first.to_s.downcase
        rescue StandardError
          to_s.downcase
        end

        def base64?
          match?(/\A[A-Za-z0-9+\/]+=*\z/) && (length % 4).zero?
        rescue StandardError
          false
        end

        def looks_like_secret?
          length >= 16 &&
            !include?(" ") &&
            match?(/[A-Z]/) &&
            match?(/[a-z]/) &&
            match?(/[0-9]/)
        rescue StandardError
          false
        end
      end
    end
  end
end
