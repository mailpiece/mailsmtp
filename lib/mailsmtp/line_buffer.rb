module MailSmtp
  # The framing half of a session's input: bytes in through +<<+, whole lines out.
  # It holds whatever piled up behind the line last handed out, so one object knows
  # where a line ends — and there is one place for STARTTLS to throw plaintext away.
  #
  # Sockets are none of its business. Something else decides when to read, how much,
  # and how long a read may take; this only ever sees the bytes that arrived.
  class LineBuffer
    # Bytes read but not handed out yet have outgrown what the caller allows behind
    # a line that is still not terminated.
    BufferOverrun = Class.new(RuntimeError)

    # Below one read's worth of dead prefix, dropping it costs more than it saves.
    COMPACTION_FLOOR = 4096

    # +pending_limit+ caps the bytes held behind an unterminated line (+nil+ for no
    # cap); +compaction_floor+ is the size the bytes arrive in, which sets how much
    # dead prefix is worth a copy to be rid of.
    def initialize(pending_limit: nil, compaction_floor: COMPACTION_FLOOR)
      @pending_limit = pending_limit
      @compaction_floor = compaction_floor
      @pending = +""
      @start = 0
      @terminator_at = nil
    end

    # Bytes exactly as they came off the wire — appended, never re-encoded, so a
    # buffer holding only ASCII stays ASCII and goes BINARY on the first high byte.
    def <<(bytes)
      # Whatever was already buffered has been searched to its end, so an append only
      # ever has to search the bytes it brings; and once a whole line is buffered the
      # terminator is already the first one, so later bytes cannot move it.
      searched_to = @pending.bytesize
      @pending << bytes
      @terminator_at ||= @pending.byteindex("\n", searched_to)
      raise BufferOverrun if @pending_limit && unread_bytes > @pending_limit

      self
    end

    # A further complete line is already buffered — which is what makes the command
    # we just took a pipelined one rather than merely the next one.
    def pending_line? = !@terminator_at.nil?

    # A command is judged whole: every CR and LF goes, not only the terminator,
    # so a bare CR cannot ride inside an address into the envelope.
    def take_command
      take_line&.delete("\r\n")
    end

    # DATA is framed by its terminator, so a body line comes back with the
    # terminator already told apart from the bytes: [ line, ended-with-CRLF ].
    # Nothing else is removed — an interior CR is the caller's to judge.
    def take_body_line
      if (line = take_line)
        [ line.sub(/\r?\n\z/, ""), line.end_with?("\r\n") ]
      end
    end

    # Everything read so far is unread again by never having been here: nothing
    # buffered before this call can be handed out after it.
    def discard_pending
      @pending.clear
      @start = 0
      @terminator_at = nil
    end

    private
      # The invariant the rest rests on: +@terminator_at+ is an absolute byte
      # offset into +@pending+ — the LF ending the next line — or +nil+ when no
      # whole line is buffered yet. It never points behind +@start+, the offset
      # the next line begins at, and every byte from there to the end has already
      # been searched. So a line is only ever handed out once it is whole and a
      # trailing CR waits for the next read instead of being judged bare at a
      # chunk edge. Offsets are byte offsets throughout: an SMTPUTF8 line carries
      # multibyte sequences that character indexing would frame in the wrong place.
      def take_line
        if @terminator_at
          line = @pending.byteslice(@start, @terminator_at + 1 - @start)
          @start = @terminator_at + 1
          @terminator_at = @pending.byteindex("\n", @start)
          compact_pending
          line
        end
      end

      # Lines are handed out by moving +@start+ rather than by shifting the buffer,
      # so the bytes behind it are dead until they are dropped all at once here.
      # Waiting until they outweigh the live bytes they cost us to move keeps the
      # shifting amortized, and the read-sized floor keeps a session of small
      # commands from copying on every line — while still leaving no way for a
      # long-lived connection to grow +@pending+ without bound.
      def compact_pending
        if @start >= @compaction_floor && @start >= unread_bytes
          @pending = @pending.byteslice(@start..)
          @terminator_at -= @start if @terminator_at
          @start = 0
        end
      end

      # What the limit is about: bytes read but not handed out yet. The dead
      # prefix is already spoken for and must not count against it.
      def unread_bytes = @pending.bytesize - @start
  end
end
