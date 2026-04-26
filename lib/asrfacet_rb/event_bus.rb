# frozen_string_literal: true
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

require "concurrent"
require "thread"
require "time"

module ASRFacet
  class EventBus
    DEFAULT_MAX_QUEUE = 1_000

    def initialize(max_queue: DEFAULT_MAX_QUEUE, logger: ASRFacet::Core::ThreadSafe)
      @handlers = Concurrent::Map.new { |hash, key| hash[key] = [] }
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
    end

    def on(event, priority: 50, &block)
      return nil unless block

      @mutex.synchronize do
        entries = Array(@handlers[event.to_sym]).dup
        entries << { priority: priority.to_i, handler: block }
        entries.sort_by! { |entry| entry[:priority] }
        @handlers[event.to_sym] = entries
      end
      true
    end

    def subscribe(event, priority: 50, &block)
      on(event, priority: priority, &block)
    end

    def emit(event, payload = {}, dispatch_now: false, non_block: false)
      return nil unless accepting?

      entry = {
        type: event.to_sym,
        data: payload,
        timestamp: Time.now.utc.iso8601
      }
      increment_stat(:emitted)

      if dispatch_now
        dispatch(entry)
        entry
      else
        queued = queue_event(entry, non_block: non_block)
        queued ? entry : nil
      end
    end

    def process_all
      loop do
        event = @queue.pop(true)
        dispatch(event)
      end
    rescue ThreadError
      true
    end

    def drain_async(workers: 10)
      Array.new([workers.to_i, 1].max) do
        Thread.new do
          loop do
            event = @queue.pop
            break if event.nil?

            dispatch(event)
          end
        end
      end
    end

    def stop(workers:)
      @mutex.synchronize { @accepting = false }
      [workers.to_i, 1].max.times { @queue << nil }
      true
    end

    def handler_count(event)
      Array(@handlers[event.to_sym]).size
    end

    def stats
      @mutex.synchronize do
        {
          emitted: @stats[:emitted],
          dispatched: @stats[:dispatched],
          dropped: @stats[:dropped],
          blocked_pushes: @stats[:blocked_pushes],
          subscribers: @handlers.each_pair.each_with_object({}) { |(event, entries), memo| memo[event] = entries.size },
          queue_depth: queue_depth,
          max_queue: @max_queue,
          accepting: @accepting
        }
      end
    end

    private

    def dispatch(event)
      handlers = Array(@handlers[event[:type]]).dup
      handlers.each do |entry|
        entry[:handler].call(event[:data])
      rescue ASRFacet::Error => e
        @logger&.print_warning("Event handler error for #{event[:type]}: #{e.message}")
      end
      increment_stat(:dispatched)
      true
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
      false
    end

    def increment_stat(key)
      @mutex.synchronize do
        @stats[key] = @stats[key].to_i + 1
      end
    end

    def queue_depth
      @queue.respond_to?(:length) ? @queue.length : @queue.size
    end

    def queue_full?
      queue_depth >= @max_queue
    end

    def accepting?
      @mutex.synchronize { @accepting }
    end
  end
end
