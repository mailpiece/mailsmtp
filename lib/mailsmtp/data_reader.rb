module MailSmtp
  # IO-like view of an SMTP DATA body: dot-unstuffed bytes ending at the "." line
  # (README). Limits are recorded, not only raised, so an unread body is not a 250.
  class DataReader
    # Absolute drain ceiling when the server has no SIZE limit configured.
    DRAIN_BYTE_CEILING = Limits::MAX_MESSAGE_SIZE

    attr_reader :failure

    def initialize(max_message_size: nil, max_line_length: Limits::MAX_TEXT_LINE_LENGTH,
      on_headers: nil, &read_line)
      raise ArgumentError, "read_line block required" unless read_line

      @read_line = read_line
      @max_message_size = max_message_size
      @max_line_length = max_line_length
      @on_headers = on_headers
      @buffer = +"".b
      @bytes_seen = 0
      @eof = false
      @failure = nil
      @draining = false
      @headers_seen = false
      @drain_ceiling_hit = false
    end

    def read(length = nil, outbuf = nil)
      raise @failure if @failure && !@draining

      # IO#read(0) returns an empty string without consuming input.
      if length == 0
        chunk = +""
        return outbuf ? outbuf.replace(chunk) : chunk
      end

      if length
        fill_until { @buffer.bytesize >= length || @eof || @failure }
      else
        fill_until { @eof || @failure }
      end

      raise @failure if @failure && !@draining

      if @buffer.empty?
        # IO#read(length) returns nil at EOF; read() with no length returns "".
        chunk = length ? nil : +""
      elsif length
        chunk = @buffer.slice!(0, length)
      else
        chunk = @buffer
        @buffer = +""
      end

      if outbuf
        outbuf.replace(chunk || +"")
        chunk
      else
        chunk
      end
    end

    def readpartial(maxlen, outbuf = nil)
      raise ArgumentError, "maxlen must be positive" unless maxlen.positive?
      raise @failure if @failure && !@draining

      # Fill up to maxlen (not "any bytes") so a peer drop is discovered on this call
      # — returning one line lets a short-read loop treat a truncated body as complete.
      fill_until { @buffer.bytesize >= maxlen || @eof || @failure }

      raise @failure if @failure && !@draining
      if @buffer.empty?
        # EOFError only after the terminating "."; a drop mid-DATA must not look
        # like a clean end-of-message to an app that rescues EOFError.
        raise EOFError, "end of data" if @eof
        raise ConnectionLost, "Connection lost during DATA"
      end

      chunk = @buffer.slice!(0, maxlen)
      outbuf ? outbuf.replace(chunk) : chunk
    end

    def eof?
      @eof && @buffer.empty? && (@draining || @failure.nil?)
    end

    def drain
      @draining = true
      @buffer = +""
      # Stop on a failure there is nothing to resynchronize for, or on the absolute
      # drain ceiling when SIZE is off / after LineTooLong — never read forever
      # waiting for a "." the client may have no way of sending.
      fill_until { @drain_ceiling_hit || @failure&.unrecoverable? }
    end

    def drain_ceiling_hit? = @drain_ceiling_hit

    def binmode = self
    def close = nil
    def closed? = false

    private
      def drain_ceiling
        @max_message_size || DRAIN_BYTE_CEILING
      end

      def fill_until
        until @eof || (!@draining && @failure) || (@draining && @drain_ceiling_hit) || yield
          pull_line
        end
      end

      def pull_line
        line = @read_line.call
        if line.nil?
          @eof = true
          return
        end

        # Count every network line toward SIZE, including ones we discard after failure.
        @bytes_seen += line.bytesize
        line = line.b

        # Recorded before the drain-ceiling stop below, which must not leave +failure+
        # nil: the default +receive+ never reads, and a nil failure means 250.
        if line.bytesize > @max_line_length
          @failure ||= LineTooLong.new
        end

        if @max_message_size && @bytes_seen > @max_message_size
          @failure ||= MessageTooLarge.new
        end

        if @draining && @bytes_seen > drain_ceiling
          @drain_ceiling_hit = true
          # Absolute ceiling (no SIZE configured): still refuse rather than 250.
          @failure ||= MessageTooLarge.new
          return
        end

        if !@draining && !@headers_seen && line == "\r\n".b
          @headers_seen = true
          @on_headers&.call
        end

        return if @draining || @failure

        @buffer << line
      rescue ServiceUnavailable
        raise
      rescue Error => e
        @failure ||= e
      end
  end

  # Prepends a fixed string once, then delegates — used for +add_received+.
  # Duck-types the same IO surface as +DataReader+.
  class PrefixedReader
    def initialize(prefix, inner)
      @prefix = prefix.to_s.b
      @inner = inner
    end

    def read(length = nil, outbuf = nil)
      # Match DataReader / IO#read(0).
      if length == 0
        chunk = +""
        return outbuf ? outbuf.replace(chunk) : chunk
      end

      if @prefix
        if length.nil?
          chunk = @prefix
          @prefix = nil
          rest = @inner.read
          chunk = rest ? "#{chunk}#{rest}" : chunk
        elsif length >= @prefix.bytesize
          chunk = @prefix
          @prefix = nil
          rest_len = length - chunk.bytesize
          rest = rest_len.positive? ? @inner.read(rest_len) : +""
          chunk = rest ? "#{chunk}#{rest}" : chunk
        else
          chunk = @prefix.slice!(0, length)
        end
        outbuf ? outbuf.replace(chunk) : chunk
      else
        @inner.read(length, outbuf)
      end
    end

    def readpartial(maxlen, outbuf = nil)
      if @prefix && !@prefix.empty?
        chunk = @prefix.slice!(0, maxlen)
        @prefix = nil if @prefix.empty?
        outbuf ? outbuf.replace(chunk) : chunk
      else
        @inner.readpartial(maxlen, outbuf)
      end
    end

    def drain
      @prefix = nil
      @inner.drain
    end

    def failure = @inner.failure
    def drain_ceiling_hit? = @inner.drain_ceiling_hit?

    def eof?
      (@prefix.nil? || @prefix.empty?) && @inner.eof?
    end

    def binmode = self
    def close = @inner.close
    def closed? = @inner.closed?
  end
end
