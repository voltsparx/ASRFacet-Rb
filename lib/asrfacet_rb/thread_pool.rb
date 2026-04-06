# Part of ASRFacet-Rb — authorized testing only
require "thread"

module ASRFacet
  class ThreadPool
    def initialize(size)
      @size = [size.to_i, 1].max
      @queue = SizedQueue.new(@size)
      @mutex = Mutex.new
      @shutdown = false
      @workers = Array.new(@size) { build_worker }
    rescue StandardError
      @size = 1
      @queue = SizedQueue.new(@size)
      @mutex = Mutex.new
      @shutdown = false
      @workers = Array.new(@size) { build_worker }
    end

    def enqueue(&block)
      return nil if @shutdown || block.nil?

      @queue.push(block)
      true
    rescue StandardError
      nil
    end

    def current_size
      @mutex.synchronize { @workers.count(&:alive?) }
    rescue StandardError
      @size
    end

    def resize(new_size)
      target = [new_size.to_i, 1].max
      @mutex.synchronize do
        return @workers.count(&:alive?) if @shutdown

        active = @workers.count(&:alive?)
        if target > active
          (target - active).times { @workers << build_worker }
        elsif target < active
          (active - target).times { @queue.push(nil) }
        end
        @size = target
      end
      target
    rescue StandardError
      current_size
    end

    def wait
      return self if @shutdown

      @shutdown = true
      worker_count = @mutex.synchronize { @workers.length }
      worker_count.times { @queue.push(nil) }
      @mutex.synchronize { @workers.dup }.each do |worker|
        worker.join
      rescue StandardError
        nil
      end
      self
    rescue StandardError
      self
    end

    private

    def build_worker
      Thread.new do
        loop do
          job = @queue.pop
          break if job.nil?

          job.call
        rescue StandardError
          nil
        end
      end
    rescue StandardError
      Thread.new {}
    end
  end
end
