# Part of ASRFacet-Rb — authorized testing only
require "thread"

module ASRFacet
  class ThreadPool
    def initialize(size)
      @size = [size.to_i, 1].max
      @queue = SizedQueue.new(@size)
      @workers = Array.new(@size) do
        Thread.new do
          loop do
            job = @queue.pop
            break if job.nil?

            begin
              job.call
            rescue StandardError
              nil
            end
          end
        rescue StandardError
          nil
        end
      end
    rescue StandardError
      @workers = []
      @queue = SizedQueue.new(1)
      @size = 1
    end

    def enqueue(&block)
      return nil unless block

      @queue.push(block)
    rescue StandardError
      nil
    end

    def wait
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
  end
end
