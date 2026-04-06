# Part of ASRFacet-Rb — authorized testing only
require "fileutils"

module ASRFacet::Output
  class BaseFormatter
    def format(_results)
      raise NotImplementedError, "Subclasses must implement #format"
    end

    def save(results, path)
      FileUtils.mkdir_p(File.dirname(path.to_s))
      File.write(path.to_s, format(results))
      path
    rescue StandardError
      nil
    end
  end
end
