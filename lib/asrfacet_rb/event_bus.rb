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

require "thread"
require "time"

module ASRFacet
  class EventBus
    DEFAULT_MAX_QUEUE = 1_000

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

    def initialize(max_queue: DEFAULT_MAX_QUEUE, logger: ASRFacet::Core::ThreadSafe)
      @subscribers = Hash.new { |hash, key| hash[key] = [] }
      @max_queue = max_queue.to_i.positive? ? max_queue.to_i : DEFAULT_MAX_QUEUE
      @queue = SizedQueue.new(@max_queue)
      @mutex = Mutex.new
      @logger = logger
      @stats = {
        emitted: 0,
        dispatched: 0,
        dropped: 0,
        blocked_pushes: 0
      }
      @accepting = true
    rescue StandardError
      @subscribers = Hash.new { |hash, key| hash[key] = [] }
      @queue = Queue.new
      @mutex = Mutex.new
      @logger = logger
      @max_queue = DEFAULT_MAX_QUEUE
      @stats = { emitted: 0, dispatched: 0, dropped: 0, blocked_pushes: 0 }
      @accepting = true
    end

    def stats
      @mutex.synchronize do
        @stats.merge(
          subscribers: @subscribers.transform_values(&:size),
          queue_depth: queue_depth,
          max_queue: @max_queue,
          accepting: @accepting
        )
      end
    rescue StandardError
      { emitted: 0, dispatched: 0, dropped: 0, blocked_pushes: 0, subscribers: {}, queue_depth: 0, max_queue: @max_queue, accepting: false }
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

    def emit(event_type, data, dispatch_now: false, non_block: false)
      return nil unless EVENT_TYPES.include?(event_type.to_sym)
      return nil unless accepting?

      event = {
        type: event_type.to_sym,
        data: data,
        timestamp: Time.now.iso8601
      }
      increment_stat(:emitted)
      if dispatch_now
        dispatched = dispatch(event)
        dispatched ? event : nil
      else
        queued = queue_event(event, non_block: non_block)
        queued ? event : nil
      end
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
      @mutex.synchronize { @accepting = false }
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
      increment_stat(:dispatched)
      true
    rescue StandardError
      nil
    end

    def queue_event(event, non_block: false)
      if non_block
        @queue.push(event, true)
      else
        increment_stat(:blocked_pushes) if queue_full?
        @queue << event
      end
      true
    rescue ThreadError
      increment_stat(:dropped)
      @logger&.print_warning("Event bus queue is full; dropping #{event[:type]} event.")
      nil
    rescue StandardError
      nil
    end

    def increment_stat(key)
      @mutex.synchronize { @stats[key] = @stats[key].to_i + 1 }
    rescue StandardError
      nil
    end

    def queue_depth
      @queue.respond_to?(:length) ? @queue.length : @queue.size
    rescue StandardError
      0
    end

    def queue_full?
      return false unless @queue.is_a?(SizedQueue)

      queue_depth >= @max_queue
    rescue StandardError
      false
    end

    def accepting?
      @mutex.synchronize { @accepting }
    rescue StandardError
      false
    end
  end
end
