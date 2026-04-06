# Part of ASRFacet-Rb — authorized testing only
require "set"
require "thread"

module ASRFacet
  class ResultStore
    def initialize
      @data = Hash.new { |hash, key| hash[key] = Set.new }
      @mutex = Mutex.new
    end

    def add(category, item)
      normalized_item = normalize_item(item)
      @mutex.synchronize do
        @data[category.to_sym] << normalized_item
      end
      normalized_item
    rescue StandardError
      nil
    end

    def all(category)
      @mutex.synchronize { @data[category.to_sym].to_a }
    rescue StandardError
      []
    end

    def to_h
      @mutex.synchronize do
        @data.each_with_object({}) do |(key, values), memo|
          memo[key] = values.to_a
        end
      end
    rescue StandardError
      {}
    end

    def summary
      @mutex.synchronize do
        @data.transform_values(&:count)
      end
    rescue StandardError
      {}
    end

    private

    def normalize_item(item)
      if item.respond_to?(:to_h) && !item.is_a?(Hash)
        item.to_h
      else
        item
      end
    rescue StandardError
      item
    end
  end
end
