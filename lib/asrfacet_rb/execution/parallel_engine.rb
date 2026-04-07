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

require "etc"
require "parallel"
require "time"

module ASRFacet
  module Execution
    class ParallelEngine
      DEFAULT_PROCESSES = [Etc.nprocessors, 4].max

      attr_reader :errors

      def initialize(processes: DEFAULT_PROCESSES, logger: ASRFacet::Core::ThreadSafe)
        @processes = [processes.to_i, 1].max
        @logger = logger
        @mutex = Mutex.new
        @errors = []
      rescue StandardError
        @processes = DEFAULT_PROCESSES
        @logger = logger
        @mutex = Mutex.new
        @errors = []
      end

      def map(items, &block)
        return [] unless block

        Parallel.map(Array(items), in_processes: @processes) do |item|
          safe_call(item, &block)
        end.compact
      rescue Parallel::DeadWorker => e
        log_error("parallel map worker died", e)
        []
      rescue StandardError => e
        log_error("parallel map failed", e)
        []
      end

      def each(items, &block)
        return [] unless block

        Parallel.each(Array(items), in_processes: @processes) do |item|
          safe_call(item, &block)
        end
      rescue Parallel::DeadWorker => e
        log_error("parallel each worker died", e)
        []
      rescue StandardError => e
        log_error("parallel each failed", e)
        []
      end

      def map_threads(items, threads: 10, &block)
        return [] unless block

        Parallel.map(Array(items), in_threads: [threads.to_i, 1].max) do |item|
          safe_call(item, &block)
        end.compact
      rescue StandardError => e
        log_error("parallel thread map failed", e)
        []
      end

      def run_all(tasks)
        task_list = Array(tasks).compact
        return [] if task_list.empty?

        Parallel.map(task_list, in_processes: [@processes, task_list.size].min) do |task|
          task.call
        rescue StandardError => e
          error_hash("parallel task failed", e)
        end
      rescue Parallel::DeadWorker => e
        log_error("parallel task worker died", e)
        task_list.map { error_hash("parallel task worker died", e) }
      rescue StandardError => e
        log_error("parallel run_all failed", e)
        task_list.map { error_hash("parallel run_all failed", e) }
      end

      private

      def safe_call(item)
        yield(item)
      rescue StandardError => e
        error_hash("parallel item failed", e, item: item)
      end

      def error_hash(context, error, item: nil)
        log_error(context, error, item: item)
        { error: error.message.to_s, error_class: error.class.name, context: context, item: item }
      rescue StandardError
        { error: "parallel execution failure", context: context, item: item }
      end

      def log_error(context, error, item: nil)
        entry = {
          context: context,
          message: error.message.to_s,
          error_class: error.class.name,
          item: item,
          timestamp: Time.now.iso8601
        }
        @mutex.synchronize { @errors << entry }
        @logger&.print_warning("#{context}: #{entry[:message]}")
        entry
      rescue StandardError
        nil
      end
    end
  end
end
