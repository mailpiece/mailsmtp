require "ipaddr"

module MailSmtp
  # Events per client address in fixed one-minute windows, held in memory. An IPv6
  # client counts by its /64, the block a single host is normally handed, so hopping
  # across its addresses does not start the count over; IPv4 counts as is.
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
      key = key_for(address)

      @mutex.synchronize do
        if window != @window
          @counts.clear
          @window = window
        end
        @counts[key] = @counts.fetch(key, 0) + 1
      end
    end

    private
      def key_for(address)
        ip = IPAddr.new(address)
        # A dual-stack listener reports IPv4 clients as ::ffff:a.b.c.d, which masked to
        # a /64 would put all of them in one bucket.
        ip = ip.native if ip.ipv4_mapped?
        ip.ipv6? ? ip.mask(64).to_s : ip.to_s
      rescue IPAddr::Error
        address
      end
  end
end
