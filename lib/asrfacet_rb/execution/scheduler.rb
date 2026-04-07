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

require "time"

module ASRFacet
  module Execution
    class Scheduler
      attr_reader :history

      def initialize(logger: ASRFacet::Core::ThreadSafe)
        @logger = logger
        @mutex = Mutex.new
        @history = []
        @throttles = {}
      rescue StandardError
        @logger = logger
        @mutex = Mutex.new
        @history = []
        @throttles = {}
      end

      def stage(name, timeout: nil)
        started_at = Time.now
        status = :success
        result = nil
        error = nil
        entry = nil

        begin
          if timeout.to_f.positive?
            runner = Thread.new do
              Thread.current.report_on_exception = false if Thread.current.respond_to?(:report_on_exception=)
              yield
            rescue StandardError => e
              Thread.current[:asrfacet_error] = e
            end

            if runner.join(timeout.to_f)
              raise runner[:asrfacet_error] if runner[:asrfacet_error]

              result = runner.value
            else
              runner.kill rescue nil
              status = :timeout
              error = TimeoutError.new("Stage #{name} exceeded #{timeout}s")
            end
          else
            result = yield
          end
        rescue StandardError => e
          status = :failed if status == :success
          error = e
          @logger&.print_warning("scheduler stage #{name} failed: #{e.message}")
        ensure
          finished_at = Time.now
          entry = {
            name: name.to_s,
            status: status,
            error: error&.message.to_s,
            error_class: error&.class&.name,
            started_at: started_at.iso8601,
            finished_at: finished_at.iso8601,
            duration_ms: ((finished_at - started_at) * 1000).round
          }
          @mutex.synchronize { @history << entry }
        end

        { status: status, result: result, error: error&.message.to_s, entry: entry }
      rescue StandardError => e
        @logger&.print_warning("scheduler stage #{name} failed to record: #{e.message}")
        { status: :failed, result: nil, error: e.message, entry: { name: name.to_s, status: :failed } }
      end

      def throttle(key, every:)
        interval = every.to_f
        return yield if interval <= 0

        wait_time = 0.0
        slot_time = monotonic_time
        @mutex.synchronize do
          last_run = @throttles[key.to_s].to_f
          wait_time = [interval - (slot_time - last_run), 0.0].max
          slot_time += wait_time
          @throttles[key.to_s] = slot_time
        end

        sleep(wait_time) if wait_time.positive?
        yield
      rescue StandardError => e
        @logger&.print_warning("scheduler throttle #{key} failed: #{e.message}")
        nil
      end

      def with_retry(max_retries: 2, base_delay: 0.25)
        attempts = 0
        begin
          attempts += 1
          yield(attempts)
        rescue StandardError => e
          raise e if attempts > max_retries.to_i

          delay = (base_delay.to_f * (2**(attempts - 1))).round(3)
          @logger&.print_warning("retry #{attempts}/#{max_retries} after failure: #{e.message}")
          sleep(delay) if delay.positive?
          retry
        end
      rescue StandardError
        nil
      end

      def schedule(items, workers: 10, queue_size: 0, timeout: nil, label: "scheduled-job", &block)
        return { results: [], errors: [], stats: {} } unless block

        task_list = Array(items)
        results = Array.new(task_list.size)
        pool = ASRFacet::Execution::ThreadPool.new(
          workers: [workers.to_i, 1].max,
          queue_size: queue_size,
          default_timeout: timeout,
          logger: @logger
        )

        task_list.each_with_index do |item, index|
          pool.enqueue(timeout: timeout, label: "#{label}-#{index}", metadata: { item: item }) do
            results[index] = block.call(item, index)
          end
        end

        pool.wait
        { results: results.compact, errors: pool.errors.dup, stats: pool.stats }
      rescue StandardError => e
        @logger&.print_warning("scheduler schedule failed: #{e.message}")
        { results: [], errors: [{ message: e.message, error_class: e.class.name }], stats: {} }
      end

      def stats
        @mutex.synchronize do
          {
            stages: @history.size,
            last_stage: @history.last,
            throttles: @throttles.keys.sort
          }
        end
      rescue StandardError
        { stages: Array(@history).size, last_stage: nil, throttles: [] }
      end

      private

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      rescue StandardError
        Time.now.to_f
      end

      class TimeoutError < StandardError; end
    end
  end
end
