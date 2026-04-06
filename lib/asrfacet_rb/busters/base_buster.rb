# Part of ASRFacet-Rb — authorized testing only
module ASRFacet::Busters
  class BaseBuster
    def run
      raise NotImplementedError, "Subclasses must implement #run"
    end
  end
end
