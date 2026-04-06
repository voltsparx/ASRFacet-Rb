# Part of ASRFacet-Rb — authorized testing only
require "thread"
require "time"

module ASRFacet
  module Core
    class CircuitBreaker
      class CircuitOpenError < StandardError; end

      STATES = {
        closed: :closed,
        open: :open,
        half_open: :half_open
      }.freeze

      DEFAULT_OPTS = {
        failure_threshold: 5,
        cooldown_seconds: 30,
        success_threshold: 2
      }.freeze

      attr_reader :name

      def initialize(name = nil, opts = {}, **legacy_opts)
        merged = DEFAULT_OPTS.merge(symbolize_keys(opts)).merge(symbolize_keys(legacy_opts))
        @name = name.to_s.empty? ? "circuit" : name.to_s
        @opts = {
          failure_threshold: positive_or_default(merged[:failure_threshold] || merged[:threshold], DEFAULT_OPTS[:failure_threshold]),
          cooldown_seconds: positive_or_default(merged[:cooldown_seconds] || merged[:cooldown], DEFAULT_OPTS[:cooldown_seconds]),
          success_threshold: positive_or_default(merged[:success_threshold], DEFAULT_OPTS[:success_threshold])
        }
        @state = STATES[:closed]
        @failure_count = 0
        @success_count = 0
        @opened_at = nil
        @mutex = Mutex.new
      rescue StandardError
        @name = name.to_s.empty? ? "circuit" : name.to_s
        @opts = DEFAULT_OPTS.dup
        @state = STATES[:closed]
        @failure_count = 0
        @success_count = 0
        @opened_at = nil
        @mutex = Mutex.new
      end

      def call
        raise CircuitOpenError, "#{@name} circuit open" unless allow?

        result = yield
        record_success
        result
      rescue CircuitOpenError
        raise
      rescue StandardError
        record_failure
        raise
      end

      def allow?
        @mutex.synchronize do
          transition_to_half_open_if_ready!
          !open?
        end
      rescue StandardError
        true
      end

      def record_failure
        @mutex.synchronize do
          transition_to_half_open_if_ready!
          @failure_count += 1
          @success_count = 0
          transition_to_open! if should_open_circuit?
        end
        true
      rescue StandardError
        nil
      end

      def record_success
        @mutex.synchronize do
          case @state
          when STATES[:half_open]
            @success_count += 1
            transition_to_closed! if @success_count >= @opts[:success_threshold]
          else
            transition_to_closed!
          end
        end
        true
      rescue StandardError
        nil
      end

      def reset
        @mutex.synchronize { transition_to_closed! }
        true
      rescue StandardError
        nil
      end

      def open?
        @state == STATES[:open]
      rescue StandardError
        false
      end

      def closed?
        @state == STATES[:closed]
      rescue StandardError
        true
      end

      def half_open?
        @state == STATES[:half_open]
      rescue StandardError
        false
      end

      def state
        @mutex.synchronize { @state }
      rescue StandardError
        STATES[:closed]
      end

      def snapshot
        @mutex.synchronize do
          {
            name: @name,
            state: @state,
            failure_count: @failure_count,
            success_count: @success_count,
            opened_at: @opened_at,
            cooldown_seconds: @opts[:cooldown_seconds],
            failure_threshold: @opts[:failure_threshold],
            success_threshold: @opts[:success_threshold]
          }
        end
      rescue StandardError
        {
          name: @name,
          state: STATES[:closed],
          failure_count: 0,
          success_count: 0,
          opened_at: nil,
          cooldown_seconds: DEFAULT_OPTS[:cooldown_seconds],
          failure_threshold: DEFAULT_OPTS[:failure_threshold],
          success_threshold: DEFAULT_OPTS[:success_threshold]
        }
      end

      private

      def should_open_circuit?
        @failure_count >= @opts[:failure_threshold] && !open?
      rescue StandardError
        false
      end

      def transition_to_open!
        @state = STATES[:open]
        @opened_at = Time.now
        @success_count = 0
        ASRFacet::Core::ThreadSafe.print_warning("Circuit opened for #{@name} — cooling down #{@opts[:cooldown_seconds]}s")
      rescue StandardError
        nil
      end

      def transition_to_closed!
        @state = STATES[:closed]
        @failure_count = 0
        @success_count = 0
        @opened_at = nil
      rescue StandardError
        nil
      end

      def transition_to_half_open_if_ready!
        return unless open?
        return if @opened_at.nil?
        return if (Time.now - @opened_at) < @opts[:cooldown_seconds]

        @state = STATES[:half_open]
        @success_count = 0
      rescue StandardError
        @state = STATES[:half_open]
      end

      def positive_or_default(value, default)
        parsed = value.to_i
        parsed.positive? ? parsed : default
      rescue StandardError
        default
      end

      def symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), memo|
          memo[key.to_sym] = value
        end
      rescue StandardError
        {}
      end
    end
  end
end
