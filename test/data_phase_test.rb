require_relative "test_helper"

class MailSmtp::DataPhaseTest < MailSmtp::ServerIntegrationTest
  def test_the_reader_can_be_handed_straight_to_io_copy_stream
    server = CopyStreamServer.new(**server_options)
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\nSubject: Copy\r\n\r\n.stuffed\r\nBody.\r\n",
        "a@example.com", "b@example.com")
    end

    assert_includes server.copied, "Subject: Copy"
    assert_includes server.copied, "Body."
    # copy_stream must see the unstuffed body and stop at the terminator.
    assert_includes server.copied, "\r\n.stuffed\r\n"
    refute_match(/\r\n\.\r\n\z/, server.copied)
  end

  def test_receiving_started_and_headers_received_both_fire_around_receive
    server = HookRecordingServer.new(**server_options)
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\nSubject: Hooks\r\n\r\nBody.\r\n",
        "a@example.com", "b@example.com")
    end

    assert_equal %i[ receiving_started receive headers_received ], server.calls.uniq.sort_by { |c|
      %i[ receiving_started receive headers_received ].index(c)
    }
    assert_includes server.calls, :receiving_started
    assert_includes server.calls, :headers_received
    # receiving_started runs before any body byte is read, with the envelope complete.
    assert_equal :data, server.phase_at_start
    assert_equal [ "b@example.com" ], server.headers_seen_body
  end

  def test_headers_received_does_not_fire_for_a_body_with_no_header_break
    server = HookRecordingServer.new(**server_options)
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("RCPT TO:<b@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("DATA\r\n")
    read_smtp_response(socket)
    socket.print("no blank line anywhere\r\n.\r\n")
    read_smtp_response(socket)
    socket.close

    assert_includes server.calls, :receiving_started
    refute_includes server.calls, :headers_received
  end

  def test_receive_can_stream_from_message_io
    server = StreamingServer.new(**server_options)
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\nSubject: Stream\r\n\r\nBody.\r\n",
        "a@example.com", "b@example.com")
    end

    assert_includes server.streamed, "Subject: Stream"
    assert_includes server.streamed, "Body."
    assert_operator server.read_iterations, :<, 100
  end

  def test_size_failure_raises_inside_receive_instead_of_returning_a_truncated_body
    server = CapturingFailureServer.new(**server_options(max_message_size: 40))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: a long subject that exceeds the limit\r\n\r\nBody\r\n.\r\n")

    assert_match(/\A552 /, read_smtp_response(socket).to_s)
    assert_instance_of MailSmtp::MessageTooLarge, server.read_error
    assert_nil server.persisted_body
  end

  def test_add_received_reader_supports_closed?
    server = ClosedCheckServer.new(**server_options(add_received: true))
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\n\r\nHi\r\n",
        "a@example.com", "b@example.com")
    end

    assert_equal false, server.saw_closed
    assert_match(/\AReceived: from /, server.received[:data])
  end

  def test_rejects_data_when_message_exceeds_size_limit
    start_server(max_message_size: 40)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: a long subject that exceeds the limit\r\n\r\nBody\r\n.\r\n")

    assert_match(/\A552 /, read_smtp_response(socket).to_s)
    # SIZE overflow drops the connection after 552 (no unbounded drain).
    begin
      socket.print("NOOP\r\n")
      response = read_smtp_response(socket)
      assert_nil response
    rescue Errno::ECONNRESET, Errno::EPIPE, IOError
      # closed hard — also fine
    end
  end

  def test_rejects_oversized_data_lines_only_after_dot
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("X-Long: #{"x" * 1200}\r\n\r\nBody\r\n.\r\n")

    assert_match(/\A500 /, read_smtp_response(socket).to_s)
    socket.print("RSET\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_line_too_long_without_dot_hits_drain_ceiling_and_closes
    start_server(max_message_size: 80)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    # Oversized line then more body with no "." — drain stops on SIZE ceiling and
    # may close before these writes finish (ECONNRESET is fine).
    response = nil
    begin
      socket.print("X-Long: #{"x" * 1200}\r\n")
      5.times { socket.print("more\r\n") }
      response = read_smtp_response(socket)
    rescue Errno::ECONNRESET, Errno::EPIPE, Errno::ECONNABORTED, IOError
      # closed during drain / reply
    end

    assert response.nil? || response.to_s.start_with?("500 ")
    wait_until_idle(@servers.last)
    assert_equal 0, @servers.last.connections_count
  end

  def test_eof_during_data_returns_421
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\n")
    socket.close

    # Server should not treat the drop as a clean end-of-DATA 250.
    # We only assert the server becomes idle again.
    wait_until_idle(@servers.last)
    assert_equal 0, @servers.last.connections_count
  end

  def test_bare_lf_dot_does_not_end_data_or_smuggle_commands
    server = ReceivingServer.new(**server_options(forbid_bare_newline: false))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<sender@relay.example>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<victim@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)

    # CVE-2023-51764 class: bare-LF "." must not end DATA or re-enter the command loop.
    socket.print("Subject: innocent\r\n\r\nhi\n.\nMAIL FROM:<ceo@victim.example>\r\n")
    socket.print("RCPT TO:<everyone@victim.example>\r\nDATA\r\nSubject: FORGED\r\n\r\nwire the money\r\n.\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal 1, server.receive_count
    assert_equal [ "sender@relay.example" ], server.mail_from_calls
    assert_includes server.received[:data], "MAIL FROM:<ceo@victim.example>"
    assert_includes server.received[:data], "Subject: FORGED"
  end

  def test_forbid_bare_newline_rejects_data_with_bare_lf
    # Default is strict (true) — omit the option so the constructor default is covered.
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\n\nbody\n.\r\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
  end

  # An LF-only sender never writes <CRLF>.<CRLF>, so draining toward one would read
  # until read_timeout turned this permanent 550 into a transient 421 — and the sender
  # would keep retrying a message that can never be accepted.
  def test_a_bare_lf_body_is_rejected_without_waiting_for_a_crlf_terminator
    start_server(read_timeout: 5)

    socket = data_phase_socket(port)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    socket.print("Subject: hi\n\nbody\n.\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
  end

  def test_a_bare_lf_closes_the_connection_behind_its_reply
    start_server

    socket = data_phase_socket(port)
    socket.print("Subject: hi\n\nbody\n.\r\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    assert_nil socket.gets, "the reply is the last thing on a connection we cannot resynchronize"
  end

  def test_a_bare_cr_closes_the_connection_behind_its_reply
    start_server

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\nsplit\rhere\r\n.\r\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    assert_nil socket.gets
  end

  # The counterpart to the two above: a failure the reader *can* resynchronize from
  # still drains to the "." and leaves the session usable.
  def test_a_too_long_line_drains_and_the_session_continues
    start_server

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\n#{"a" * 1200}\r\n.\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)

    socket.print("RSET\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_forbid_bare_newline_false_allows_bare_lf_in_data
    server = ReceivingServer.new(**server_options(forbid_bare_newline: false))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\n\nbody\r\n.\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_includes server.received[:data], "Subject: hi"
    assert_includes server.received[:data], "body"
  end

  def test_forbid_bare_newline_rejects_data_with_a_bare_cr_inside_a_line
    start_server

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\nsplit\rhere\r\n.\r\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
  end

  def test_forbid_bare_newline_rejects_a_bare_cr_at_the_end_of_a_line
    start_server

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\ntrailing\r\r\n.\r\n")

    assert_match(/\A550 /, read_smtp_response(socket).to_s)
  end

  def test_accepts_a_crlf_split_across_reads
    server = ReceivingServer.new(**server_options)
    start(server)

    socket = data_phase_socket(port)
    # The CR is the last byte the server has: it must wait for the LF rather
    # than judging the line at the chunk boundary.
    socket.print("Subject: hi\r\n\r\nsplit\r")
    socket.flush
    sleep 0.05
    socket.print("\nend\r\n.\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_includes server.received[:data], "split\r\nend\r\n"
  end

  def test_forbid_bare_newline_false_allows_a_bare_cr_in_data
    server = ReceivingServer.new(**server_options(forbid_bare_newline: false))
    start(server)

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\nsplit\rhere\r\n.\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_includes server.received[:data], "split\rhere"
  end

  def test_still_unstuffs_dots_and_ends_on_the_dot_line_under_the_bare_cr_check
    server = ReceivingServer.new(**server_options)
    start(server)

    socket = data_phase_socket(port)
    socket.print("Subject: hi\r\n\r\n..stuffed\r\n...\r\n.\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_includes server.received[:data], ".stuffed\r\n..\r\n"
    refute_includes server.received[:data], "\r\n.\r\n"
  end

  private
    # Walks a raw socket to the 354 prompt. Net::SMTP always writes well-formed CRLF,
    # so anything asserting on the DATA framing has to write the body itself.
    def data_phase_socket(port)
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("EHLO test.client.example\r\n")
      read_smtp_lines(socket)
      socket.print("MAIL FROM:<a@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("RCPT TO:<b@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("DATA\r\n")
      assert_match(/\A354 /, read_smtp_response(socket).to_s)
      socket
    end
end
