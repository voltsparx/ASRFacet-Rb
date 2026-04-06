# Part of ASRFacet-Rb — authorized testing only
require "thread"

module ASRFacet
  class ThreadPool
    def initialize(size)
      @size = [size.to_i, 1].max
      @queue = SizedQueue.new(@size)
      @shutdown = false
      @workers = Array.new(@size) { build_worker }
    rescue StandardError
      @size = 1
      @queue = SizedQueue.new(@size)
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

    def wait
      return self if @shutdown

      @shutdown = true
      @size.times { @queue.push(nil) }
      @workers.each do |worker|
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
