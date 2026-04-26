# frozen_string_literal: true
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

module ASRFacet
  PROFILES = {
    "cautious" => {
      threads: 25,
      ports: "top100",
      memory: true,
      monitor: false,
      timeout: 15,
      desc: "Low-noise, confirmation-first. Good for sensitive targets."
    },
    "balanced" => {
      threads: 50,
      ports: "top100",
      memory: true,
      monitor: true,
      timeout: 10,
      desc: "Standard engagement baseline. Recommended default."
    },
    "deep" => {
      threads: 100,
      ports: "top1000",
      memory: false,
      monitor: true,
      timeout: 8,
      desc: "Broader coverage. More noise. Use in safe lab environments."
    }
  }.freeze

  def self.apply_profile(profile_name, options)
    profile = PROFILES[profile_name.to_s.downcase]
    raise ASRFacet::Error, "Unknown profile: #{profile_name}" unless profile

    profile.each do |key, value|
      next if key == :desc

      options[key] ||= value
    end
    options
  end
end
