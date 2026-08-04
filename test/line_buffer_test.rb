require_relative "test_helper"

class MailSmtp::LineBufferTest < MailSmtp::TestCase
  # Fixed so a failing case can be reproduced by running the suite again.
  PROPERTY_SEED = 20_260_803
  PROPERTY_CASES = 300
  # Bytes a line is built from: terminators whole and in halves, dot-stuffing, NUL,
  # multibyte sequences and a lone continuation byte that is not valid UTF-8.
  PROPERTY_ALPHABET = [ "\r", "\n", "\r\n", ".", "..", "\0", "A", "b", " ", "\t",
    "é", "\xC3", "\xF0\x9F\x92\xA9" ].map(&:b).freeze

  def test_takes_a_command_once_the_line_is_whole
    buffer = MailSmtp::LineBuffer.new

    buffer << "EHLO exam"
    assert_nil buffer.take_command

    buffer << "ple.com\r\n"
    assert_equal "EHLO example.com", buffer.take_command
    assert_nil buffer.take_command
  end

  # The one that a naive "does the chunk end in CR?" reader gets wrong: the CR is
  # only a terminator once the LF behind it has arrived, and it may arrive later.
  def test_a_cr_at_a_chunk_edge_waits_for_the_lf
    buffer = MailSmtp::LineBuffer.new

    buffer << "MAIL FROM:<a@b>\r"
    assert_nil buffer.take_command
    refute_predicate buffer, :pending_line?

    buffer << "\nRCPT TO:<c@d>\r\n"
    assert_equal "MAIL FROM:<a@b>", buffer.take_command
    assert_equal "RCPT TO:<c@d>", buffer.take_command
  end

  # A bare CR inside a command would otherwise ride into the envelope as part of an
  # address, so a command loses every CR and LF, not only its terminator.
  def test_take_command_strips_every_cr_and_lf_not_only_the_terminator
    buffer = MailSmtp::LineBuffer.new
    buffer << "MAIL FROM:<a@b>\rRCPT TO:<c@d>\r\n"

    assert_equal "MAIL FROM:<a@b>RCPT TO:<c@d>", buffer.take_command
  end

  def test_bare_lf_ends_a_line_and_is_reported_as_not_crlf
    buffer = MailSmtp::LineBuffer.new
    buffer << "one\ntwo\r\n"

    assert_equal [ "one", false ], buffer.take_body_line
    assert_equal [ "two", true ], buffer.take_body_line
  end

  # DATA framing tells the terminator apart from the bytes and removes nothing else:
  # an interior CR is the caller's to refuse.
  def test_bare_cr_stays_in_a_body_line_for_the_caller_to_judge
    buffer = MailSmtp::LineBuffer.new
    buffer << "hel\rlo\r\n"

    assert_equal [ "hel\rlo", true ], buffer.take_body_line
  end

  def test_a_body_line_may_be_empty
    buffer = MailSmtp::LineBuffer.new
    buffer << "\r\n\n"

    assert_equal [ "", true ], buffer.take_body_line
    assert_equal [ "", false ], buffer.take_body_line
    assert_nil buffer.take_body_line
  end

  def test_pipelined_lines_come_back_in_order
    buffer = MailSmtp::LineBuffer.new
    buffer << "EHLO a\r\nMAIL FROM:<b@c>\r\nRCPT TO:<d@e>\r\nDATA\r\n"

    assert_equal [ "EHLO a", "MAIL FROM:<b@c>", "RCPT TO:<d@e>", "DATA" ],
      4.times.map { buffer.take_command }
    assert_nil buffer.take_command
  end

  # What makes a command pipelined rather than merely next: another whole line is
  # already here, before we ever went back to the socket for it.
  def test_pending_line_reports_only_a_whole_further_line
    buffer = MailSmtp::LineBuffer.new

    buffer << "EHLO a\r\nMAIL"
    assert_predicate buffer, :pending_line?

    # Half a command behind the one we take is not a pipelined command yet.
    assert_equal "EHLO a", buffer.take_command
    refute_predicate buffer, :pending_line?

    buffer << " FROM:<b@c>\r\nRCPT TO:<d@e>\r\n"
    assert_equal "MAIL FROM:<b@c>", buffer.take_command
    assert_predicate buffer, :pending_line?

    assert_equal "RCPT TO:<d@e>", buffer.take_command
    refute_predicate buffer, :pending_line?
  end

  def test_appending_after_a_whole_line_is_buffered_keeps_the_first_terminator
    buffer = MailSmtp::LineBuffer.new
    buffer << "NOOP\r\n"
    buffer << "QUIT\r\n"

    assert_equal "NOOP", buffer.take_command
    assert_equal "QUIT", buffer.take_command
  end

  def test_over_long_line_raises_buffer_overrun
    buffer = MailSmtp::LineBuffer.new(pending_limit: 16)

    buffer << ("x" * 16)
    assert_raises(MailSmtp::LineBuffer::BufferOverrun) { buffer << "y" }
  end

  # The bytes are appended and framed before the limit is judged, so what the
  # refused append brought is still there to be read.
  def test_an_overrunning_append_still_frames_what_it_appended
    buffer = MailSmtp::LineBuffer.new(pending_limit: 4)

    assert_raises(MailSmtp::LineBuffer::BufferOverrun) { buffer << "hello\r\n" }
    assert_predicate buffer, :pending_line?
    assert_equal "hello", buffer.take_command
  end

  # The limit is about bytes held behind an unterminated line. Lines already handed
  # out are spoken for — here they pile up well past the limit as a dead prefix no
  # compaction is due to drop yet, and none of it may count.
  def test_bytes_already_handed_out_do_not_count_toward_the_limit
    buffer = MailSmtp::LineBuffer.new(pending_limit: 16, compaction_floor: 4_096)

    100.times do
      buffer << "NOOP\r\n"
      assert_equal "NOOP", buffer.take_command
    end

    assert_operator buffer.instance_variable_get(:@pending).bytesize, :>, 16
  end

  def test_no_limit_holds_an_unterminated_line_of_any_size
    buffer = MailSmtp::LineBuffer.new(pending_limit: nil)

    100.times { buffer << ("x" * 1_000) }
    buffer << "\r\n"

    assert_equal 100_000, buffer.take_command.bytesize
  end

  # RFC 3207 §4.2 / CVE-2011-0411: everything read before the tunnel was up could
  # have been written by a MITM, so nothing buffered may survive the swap.
  def test_discard_pending_drops_everything_read_before_it
    buffer = MailSmtp::LineBuffer.new
    buffer << "EHLO evil\r\nAUTH PLAIN c2VjcmV0\r\nMAIL FROM:<a@b>\r\n"
    assert_equal "EHLO evil", buffer.take_command

    buffer.discard_pending

    refute_predicate buffer, :pending_line?
    assert_nil buffer.take_command

    buffer << "EHLO tunnel\r\n"
    assert_equal "EHLO tunnel", buffer.take_command
    assert_nil buffer.take_command
  end

  # The half-line case: a discarded prefix must not be spliced onto the first bytes
  # that arrive inside the tunnel either.
  def test_discard_pending_cannot_splice_a_partial_line_onto_later_bytes
    buffer = MailSmtp::LineBuffer.new
    buffer << "MAIL FROM:<evil"

    buffer.discard_pending
    buffer << "@example.com>\r\n"

    assert_equal "@example.com>", buffer.take_command
  end

  # SMTPUTF8 carries multibyte sequences, and a chunk can split one. Framing is on
  # bytes throughout, so where the split falls cannot move a line boundary.
  def test_multibyte_line_is_framed_on_bytes_not_characters
    line = "MAIL FROM:<ünïcødé@exämple.com> SMTPUTF8\r\n".b

    (1...line.bytesize).each do |split|
      buffer = MailSmtp::LineBuffer.new
      buffer << line.byteslice(0, split)
      buffer << line.byteslice(split..)

      assert_equal line.byteslice(0, line.bytesize - 2), buffer.take_command
    end
  end

  # A buffer that has only seen ASCII stays ASCII; the first high byte turns it
  # BINARY, and the lines handed out carry whatever the bytes made it.
  def test_encoding_follows_the_bytes_that_arrive
    buffer = MailSmtp::LineBuffer.new
    buffer << "NOOP\r\n"
    assert_equal Encoding::UTF_8, buffer.take_command.encoding

    buffer << "HELO \xC3\xA9\r\n".b
    line, = buffer.take_body_line
    assert_equal Encoding::BINARY, line.encoding
    assert_equal "HELO \xC3\xA9".b, line
  end

  # Lines are handed out by moving a cursor, so the bytes behind it have to be
  # dropped eventually or a long-lived session grows without bound. Reaching for
  # the buffer itself is the only way to see it — that is the whole point of it.
  def test_dead_prefix_is_compacted_so_a_long_session_stays_bounded
    buffer = MailSmtp::LineBuffer.new(compaction_floor: 64)
    peak = 0

    10_000.times do
      buffer << "NOOP\r\n"
      assert_equal "NOOP", buffer.take_command
      peak = [ peak, buffer.instance_variable_get(:@pending).bytesize ].max
    end

    assert_operator peak, :<, 128
  end

  # Whatever the chunking, the lines handed out are exactly the complete lines the
  # bytes themselves hold — and the unterminated remainder is not handed out at all.
  def test_random_input_frames_the_lines_the_bytes_themselves_hold
    each_random_case do |content, buffer, rng|
      taken = feed(content, buffer, rng) do
        if (body = buffer.take_body_line)
          line, crlf = body
          crlf ? "#{line}\r\n" : "#{line}\n"
        end
      end

      assert_equal complete_lines(content), taken
      refute_predicate buffer, :pending_line?
    end
  end

  def test_random_input_frames_commands_with_every_cr_and_lf_gone
    each_random_case do |content, buffer, rng|
      taken = feed(content, buffer, rng) { buffer.take_command }

      assert_equal complete_lines(content).map { |line| line.delete("\r\n") }, taken
    end
  end

  private
    def each_random_case
      rng = Random.new(PROPERTY_SEED)

      PROPERTY_CASES.times do
        content = random_content(rng)
        buffer = MailSmtp::LineBuffer.new(
          compaction_floor: [ 1, 2, 7, 64, 4096 ].sample(random: rng),
          pending_limit: nil
        )

        yield content, buffer, rng
      end
    end

    def random_content(rng)
      rng.rand(1..6).times.map do
        body = rng.rand(0..10).times.map { PROPERTY_ALPHABET.sample(random: rng) }.join
        body + [ "\r\n", "\n", "\r\n", "" ].sample(random: rng)
      end.join.b
    end

    # Feeds the content in randomly sized chunks, draining after each one, which is
    # what a session does: a read, then every line that read completed.
    def feed(content, buffer, rng)
      taken = []
      offset = 0

      while offset < content.bytesize
        size = rng.rand(1..9)
        buffer << content.byteslice(offset, size)
        offset += size

        while (line = yield)
          taken << line
        end
      end

      taken
    end

    def complete_lines(content)
      content.each_line("\n").select { |line| line.end_with?("\n") }
    end
end
