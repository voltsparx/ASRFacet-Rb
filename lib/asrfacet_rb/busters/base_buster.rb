# Part of ASRFacet-Rb — authorized testing only
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
