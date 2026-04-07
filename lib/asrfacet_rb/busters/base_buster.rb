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

module ASRFacet::Busters
  class BaseBuster
    include ASRFacet::Core::PluginSDK

    attr_writer :logger, :http_client, :event_bus, :config

    def self.plugin_type
      :buster
    rescue StandardError
      :buster
    end

    def run
      raise NotImplementedError, "Subclasses must implement #run"
    end
  end
end
