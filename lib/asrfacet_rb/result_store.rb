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
      @mutex.synchronize do
        @data[category.to_sym] << item
      end
      item
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
  end
end
