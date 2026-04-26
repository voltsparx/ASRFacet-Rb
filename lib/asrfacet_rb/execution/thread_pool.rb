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
  module Execution
    class ThreadPool
      STOP = Object.new.freeze

      attr_reader :completed, :errors, :failed, :timed_out

      def initialize(workers: 50, queue_size: 0, default_timeout: nil, logger: ASRFacet::Core::ThreadSafe)
        @logger = logger
        @mutex = Mutex.new
        @queue = queue_size.to_i.positive? ? SizedQueue.new(queue_size.to_i) : Queue.new
        @worker_target = normalize_workers(workers)
        @default_timeout = positive_number(default_timeout)
        @accepting = true
        @shutdown = false
        @completed = 0
        @failed = 0
        @timed_out = 0
        @errors = []
        @active_jobs = {}
        @next_job_id = 0
        @workers = Array.new(@worker_target) { build_worker }
      rescue StandardError => e
        @logger&.print_warning("Thread pool initialization degraded: #{e.message}")
        @mutex ||= Mutex.new
        @queue ||= Queue.new
        @worker_target ||= 1
        @default_timeout ||= nil
        @accepting = true if @accepting.nil?
        @shutdown = false if @shutdown.nil?
        @completed ||= 0
        @failed ||= 0
        @timed_out ||= 0
        @errors ||= []
        @active_jobs ||= {}
        @next_job_id ||= 0
        @workers ||= [build_worker]
      end

      def enqueue(timeout: nil, label: nil, metadata: {}, &block)
        return nil if block.nil? || closed?

        job = {
          id: next_job_id,
          block: block,
          label: label.to_s.empty? ? "job-#{@next_job_id}" : label.to_s,
          timeout: positive_number(timeout) || @default_timeout,
          metadata: metadata || {},
          enqueued_at: monotonic_time
        }
        @queue << job
        job[:id]
      rescue StandardError => e
        record_error("queue", e, label: label, metadata: metadata)
        nil
      end

      def current_size
        @mutex.synchronize do
          @workers.reject! { |worker| !worker.alive? }
          @workers.count(&:alive?)
        end
      rescue StandardError
        @worker_target
      end

      def resize(new_size)
        target = normalize_workers(new_size)
        return current_size if closed?

        @mutex.synchronize do
          alive = @workers.count(&:alive?)
          if target > alive
            (target - alive).times { @workers << build_worker }
          elsif target < alive
            (alive - target).times { @queue << STOP }
          end
          @worker_target = target
        end
        target
      rescue StandardError => e
        record_error("resize", e, label: "thread-pool-resize")
        current_size
      end

      def wait
        finalize_workers
        self
      rescue StandardError => e
        record_error("wait", e, label: "thread-pool-wait")
        self
      end

      def shutdown(graceful: true)
        graceful ? wait : terminate_workers
      rescue StandardError => e
        record_error("shutdown", e, label: "thread-pool-shutdown")
        self
      end

      def stats
        @mutex.synchronize do
          {
            workers: @worker_target,
            alive_workers: @workers.count(&:alive?),
            queued: queue_size,
            active: @active_jobs.size,
            completed: @completed,
            failed: @failed,
            timed_out: @timed_out,
            errors: @errors.size,
            oldest_active_seconds: oldest_active_seconds
          }
        end
      rescue StandardError
        {
          workers: @worker_target,
          alive_workers: current_size,
          queued: 0,
          active: 0,
          completed: @completed,
          failed: @failed,
          timed_out: @timed_out,
          errors: Array(@errors).size,
          oldest_active_seconds: 0
        }
      end

      def closed?
        @mutex.synchronize { @shutdown || !@accepting }
      rescue StandardError
        true
      end

      private

      def build_worker
        Thread.new do
          Thread.current.report_on_exception = false if Thread.current.respond_to?(:report_on_exception=)
          loop do
            job = @queue.pop
            break if job.equal?(STOP) || job.nil?

            execute_job(job)
          rescue StandardError => e
            record_error("worker_loop", e, label: "worker-loop")
          end
        end
      rescue StandardError => e
        record_error("worker_init", e, label: "worker-init")
        Thread.new {}
      end

      def execute_job(job)
        register_active_job(job)

        if job[:timeout]
          runner = Thread.new do
            Thread.current.report_on_exception = false if Thread.current.respond_to?(:report_on_exception=)
            job[:block].call
          rescue StandardError => e
            Thread.current[:asrfacet_rb_error] = e
          end

          if runner.join(job[:timeout])
            raise runner[:asrfacet_rb_error] if runner[:asrfacet_rb_error]

            mark_completed
          else
            runner.kill rescue nil
            mark_timeout(job)
          end
        else
          job[:block].call
          mark_completed
        end
      rescue StandardError => e
        mark_failed(job, e)
      ensure
        unregister_active_job(job)
      end

      def register_active_job(job)
        @mutex.synchronize do
          @active_jobs[job[:id]] = {
            label: job[:label],
            started_at: monotonic_time,
            timeout: job[:timeout],
            metadata: job[:metadata]
          }
        end
      rescue StandardError
        nil
      end

      def unregister_active_job(job)
        @mutex.synchronize { @active_jobs.delete(job[:id]) }
      rescue StandardError
        nil
      end

      def mark_completed
        @mutex.synchronize { @completed += 1 }
      rescue StandardError
        nil
      end

      def mark_failed(job, error)
        @mutex.synchronize { @failed += 1 }
        record_error("job_failure", error, label: job[:label], metadata: job[:metadata])
      rescue StandardError
        nil
      end

      def mark_timeout(job)
        error = TimeoutError.new("Job #{job[:label]} exceeded #{job[:timeout]}s")
        @mutex.synchronize do
          @failed += 1
          @timed_out += 1
        end
        record_error("job_timeout", error, label: job[:label], metadata: job[:metadata])
      rescue StandardError
        nil
      end

      def finalize_workers
        workers = []
        @mutex.synchronize do
          return @workers if @shutdown

          @accepting = false
          @shutdown = true
          workers = @workers.dup
        end

        workers.count.times { @queue << STOP }
        workers.each do |worker|
          worker.join
        rescue StandardError
          nil
        end
      end

      def terminate_workers
        workers = []
        @mutex.synchronize do
          @accepting = false
          @shutdown = true
          workers = @workers.dup
        end

        workers.each do |worker|
          worker&.kill
        rescue StandardError
          nil
        end
        self
      rescue StandardError
        self
      end

      def record_error(kind, error, label:, metadata: {})
        entry = {
          type: kind,
          label: label.to_s,
          message: error.message.to_s,
          error_class: error.class.name,
          metadata: metadata || {},
          timestamp: Time.now.iso8601
        }
        @mutex.synchronize { @errors << entry }
        @logger&.print_warning("[pool] #{entry[:label]} failed: #{entry[:message]}") if kind.to_s.include?("timeout")
        entry
      rescue StandardError
        nil
      end

      def queue_size
        @queue.respond_to?(:length) ? @queue.length : @queue.size
      rescue StandardError
        0
      end

      def oldest_active_seconds
        now = monotonic_time
        @active_jobs.values.map { |job| now - job[:started_at].to_f }.max.to_f.round(3)
      rescue StandardError
        0.0
      end

      def normalize_workers(value)
        workers = value.to_i
        workers.positive? ? workers : 1
      rescue StandardError
        1
      end

      def positive_number(value)
        numeric = value.to_f
        numeric.positive? ? numeric : nil
      rescue StandardError
        nil
      end

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      rescue StandardError
        Time.now.to_f
      end

      def next_job_id
        @mutex.synchronize do
          @next_job_id += 1
        end
      rescue StandardError
        rand(1_000_000)
      end

      class TimeoutError < StandardError; end
    end
  end
end
