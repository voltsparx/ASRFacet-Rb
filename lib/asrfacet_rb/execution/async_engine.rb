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

begin
  require "async"
  require "async/http/internet"
  ASRFACET_ASYNC_AVAILABLE = true
rescue LoadError
  ASRFACET_ASYNC_AVAILABLE = false
end

module ASRFacet
  module Execution
    class AsyncEngine
      attr_reader :errors

      def initialize(logger: ASRFacet::Core::ThreadSafe)
        @logger = logger
        @mutex = Mutex.new
        @errors = []
      rescue StandardError
        @logger = logger
        @mutex = Mutex.new
        @errors = []
      end

      def available?
        ASRFACET_ASYNC_AVAILABLE
      rescue StandardError
        false
      end

      def run(&block)
        return nil unless block
        return yield(nil) unless available?

        result = nil
        Async do |task|
          result = yield(task)
        end.wait
        result
      rescue StandardError => e
        log_error("async run failed", e)
        nil
      end

      def gather(tasks)
        task_list = Array(tasks).compact
        return [] if task_list.empty?

        if available?
          results = Array.new(task_list.size)
          Async do |parent|
            task_list.each_with_index do |callable, index|
              parent.async do
                results[index] = callable.call
              rescue StandardError => e
                results[index] = error_hash("async task failed", e, index: index)
              end
            end
          end.wait
          results
        else
          fallback_gather(task_list)
        end
      rescue StandardError => e
        log_error("async gather failed", e)
        []
      end

      def with_timeout(seconds, &block)
        return nil unless block

        if available?
          result = nil
          Async do |task|
            result = task.with_timeout(seconds.to_f, &block)
          end.wait
          result
        else
          pool = ASRFacet::Execution::ThreadPool.new(workers: 1, default_timeout: seconds, logger: @logger)
          output = Queue.new
          pool.enqueue(timeout: seconds, label: "async-timeout") { output << block.call }
          pool.wait
          output.pop(true)
        end
      rescue ThreadError
        nil
      rescue StandardError => e
        log_error("async timeout failed", e)
        nil
      end

      def fetch_all(urls, headers: {})
        url_list = Array(urls).compact
        return {} if url_list.empty?

        return async_fetch_all(url_list, headers: headers) if available?

        client = ASRFacet::HTTP::RetryableClient.new
        url_list.each_with_object({}) do |url, memo|
          response = client.get(url.to_s, headers: headers)
          memo[url.to_s] = if response
                             { status: response.code.to_i, body: response.body.to_s }
                           else
                             {}
                           end
        rescue StandardError => e
          memo[url.to_s] = error_hash("async fetch fallback failed", e, url: url)
        end
      rescue StandardError => e
        log_error("async fetch_all failed", e)
        {}
      end

      private

      def async_fetch_all(urls, headers: {})
        results = {}
        internet = nil
        Async do |parent|
          internet = ::Async::HTTP::Internet.new
          urls.each do |url|
            parent.async do
              response = internet.get(url.to_s, headers)
              results[url.to_s] = {
                status: response.status.to_i,
                body: response.read.to_s
              }
            rescue StandardError => e
              results[url.to_s] = error_hash("async fetch failed", e, url: url)
            end
          end
        ensure
          internet&.close
        end.wait
        results
      rescue StandardError => e
        log_error("async http failed", e)
        {}
      ensure
        internet&.close rescue nil
      end

      def fallback_gather(task_list)
        pool = ASRFacet::Execution::ThreadPool.new(workers: [task_list.size, 10].min, logger: @logger)
        results = Array.new(task_list.size)
        task_list.each_with_index do |callable, index|
          pool.enqueue(label: "async-fallback-#{index}") do
            results[index] = callable.call
          rescue StandardError => e
            results[index] = error_hash("async fallback task failed", e, index: index)
          end
        end
        pool.wait
        results
      rescue StandardError => e
        log_error("async fallback gather failed", e)
        []
      end

      def error_hash(context, error, data = {})
        log_error(context, error, data)
        data.merge(error: error.message.to_s, error_class: error.class.name, context: context)
      rescue StandardError
        data.merge(error: "async execution failure", context: context)
      end

      def log_error(context, error, data = {})
        entry = data.merge(
          context: context,
          message: error.message.to_s,
          error_class: error.class.name,
          timestamp: Time.now.iso8601
        )
        @mutex.synchronize { @errors << entry }
        @logger&.print_warning("#{context}: #{entry[:message]}")
        entry
      rescue StandardError
        nil
      end
    end
  end
end
