# Part of ASRFacet-Rb — authorized testing only
require "thread"
require "time"

module ASRFacet
  class EventBus
    EVENT_TYPES = %i[
      domain
      subdomain
      dns_record
      ip_address
      open_port
      http_response
      ssl_cert
      finding
      error
      asn
      crawl
      js_endpoint
      correlation
      service
      stage
    ].freeze

    def initialize
      @subscribers = Hash.new { |hash, key| hash[key] = [] }
      @queue = Queue.new
      @mutex = Mutex.new
    end

    def subscribe(event_type, &block)
      return nil unless EVENT_TYPES.include?(event_type.to_sym) && block

      @mutex.synchronize do
        @subscribers[event_type.to_sym] << block
      end
      true
    rescue StandardError
      nil
    end

    def emit(event_type, data, dispatch_now: false)
      return nil unless EVENT_TYPES.include?(event_type.to_sym)

      event = {
        type: event_type.to_sym,
        data: data,
        timestamp: Time.now.iso8601
      }
      if dispatch_now
        dispatch(event)
      else
        @queue << event
      end
      event
    rescue StandardError
      nil
    end

    def process_all
      loop do
        event = @queue.pop(true)
        dispatch(event)
      end
    rescue ThreadError
      true
    rescue StandardError
      nil
    end

    def drain_async(workers: 10)
      count = [workers.to_i, 1].max
      Array.new(count) do
        Thread.new do
          loop do
            event = @queue.pop
            break if event.nil?

            dispatch(event)
          rescue StandardError
            nil
          end
        end
      end
    rescue StandardError
      []
    end

    def stop(workers:)
      [workers.to_i, 1].max.times { @queue << nil }
      true
    rescue StandardError
      nil
    end

    private

    def dispatch(event)
      handlers = @mutex.synchronize { @subscribers[event[:type]].dup }
      handlers.each do |handler|
        handler.call(event[:data])
      rescue StandardError
        nil
      end
      true
    rescue StandardError
      nil
    end
  end
end
