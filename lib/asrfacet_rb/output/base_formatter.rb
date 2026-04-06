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

    protected

    def payload_for(results)
      if results.is_a?(Hash)
        payload = symbolize_keys(results)
        payload[:store] = normalize_store(payload[:store] || payload)
        payload
      else
        { store: normalize_store(results) }
      end
    rescue StandardError
      { store: {} }
    end

    def normalize_store(store)
      return {} if store.nil?
      return symbolize_keys(store.to_h) if store.respond_to?(:to_h)

      symbolize_keys(store)
    rescue StandardError
      {}
    end

    def symbolize_keys(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested), memo|
          memo[key.to_sym] = symbolize_keys(nested)
        end
      when Array
        value.map { |entry| symbolize_keys(entry) }
      else
        value
      end
    rescue StandardError
      {}
    end
  end
end
