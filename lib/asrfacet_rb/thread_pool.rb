# Part of ASRFacet-Rb — authorized testing only
require "thread"

module ASRFacet
  class ThreadPool
    attr_reader :results

    def initialize(size)
      @size = [size.to_i, 1].max
      @queue = SizedQueue.new(@size * 4)
      @results = []
      @results_mutex = Mutex.new
      @shutdown = false
      install_interrupt_handler
      @workers = Array.new(@size) { build_worker }
    rescue StandardError
      @size = 1
      @queue = SizedQueue.new(4)
      @results = []
      @results_mutex = Mutex.new
      @shutdown = false
      @workers = Array.new(@size) { build_worker }
    end

    def enqueue(*args, **kwargs, &block)
      return nil if @shutdown || block.nil?

      @queue.push([block, args, kwargs])
      true
    rescue StandardError
      nil
    end

    def wait
      shutdown unless @shutdown
      @workers.each do |worker|
        worker.join
      rescue StandardError
        nil
      end
      self
    rescue StandardError
      self
    end

    def shutdown
      return if @shutdown

      @shutdown = true
      @size.times { @queue.push(nil) }
      true
    rescue StandardError
      nil
    end

    private

    def build_worker
      Thread.new do
        loop do
          payload = @queue.pop
          break if payload.nil?

          job, args, kwargs = payload
          result = kwargs.empty? ? job.call(*args) : job.call(*args, **kwargs)
          next if result.nil?

          @results_mutex.synchronize { @results << result }
        rescue StandardError
          nil
        end
      end
    rescue StandardError
      Thread.new {}
    end

    def install_interrupt_handler
      trap("INT") do
        shutdown
        raise Interrupt
      end
    rescue StandardError
      nil
    end
  end
end
