module MailSmtp
  # Events per client (+ClientKey+) in fixed one-minute windows, held in memory.
  class RateLimiter
    WINDOW_SECONDS = 60

    def initialize
      @counts = {}
      @window = nil
      @mutex = Mutex.new
    end

    # Records one event for +address+ and returns its count in the current window,
    # this event included. The counts only ever belong to one window, so a call
    # from a later one starts them all over.
    def count(address, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
      window = now.div(WINDOW_SECONDS)
      key = ClientKey.of(address)

      @mutex.synchronize do
        if window != @window
          @counts.clear
          @window = window
        end
        @counts[key] = @counts.fetch(key, 0) + 1
      end
    end
  end
end
