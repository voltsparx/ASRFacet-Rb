# Part of ASRFacet-Rb — authorized testing only
require "thread"
require "time"

module ASRFacet
  module Core
    class CircuitBreaker
      attr_reader :threshold, :cooldown

      def initialize(threshold: 3, cooldown: 60)
        @threshold = threshold.to_i.positive? ? threshold.to_i : 3
        @cooldown = cooldown.to_i.positive? ? cooldown.to_i : 60
        @failures = 0
        @opened_at = nil
        @mutex = Mutex.new
      rescue StandardError
        @threshold = 3
        @cooldown = 60
        @failures = 0
        @opened_at = nil
        @mutex = Mutex.new
      end

      def allow?
        @mutex.synchronize do
          reset_if_elapsed!
          @opened_at.nil?
        end
      rescue StandardError
        true
      end

      def record_success
        @mutex.synchronize do
          @failures = 0
          @opened_at = nil
        end
        true
      rescue StandardError
        nil
      end

      def record_failure
        @mutex.synchronize do
          reset_if_elapsed!
          @failures += 1
          @opened_at ||= Time.now.utc.iso8601 if @failures >= @threshold
        end
        true
      rescue StandardError
        nil
      end

      def open?
        @mutex.synchronize do
          reset_if_elapsed!
          !@opened_at.nil?
        end
      rescue StandardError
        false
      end

      def state
        @mutex.synchronize do
          reset_if_elapsed!
          {
            threshold: @threshold,
            cooldown: @cooldown,
            failures: @failures,
            open: !@opened_at.nil?,
            opened_at: @opened_at
          }
        end
      rescue StandardError
        { threshold: @threshold, cooldown: @cooldown, failures: 0, open: false, opened_at: nil }
      end

      private

      def reset_if_elapsed!
        return if @opened_at.nil?

        opened_time = Time.iso8601(@opened_at)
        return if (Time.now.utc - opened_time) < @cooldown

        @failures = 0
        @opened_at = nil
      rescue StandardError
        @failures = 0
        @opened_at = nil
      end
    end
  end
end
