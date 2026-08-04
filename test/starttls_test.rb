require_relative "test_helper"

class MailSmtp::StarttlsTest < MailSmtp::ServerIntegrationTest
  def test_tls_reader_override_is_used_for_starttls
    server = TlsReaderOverrideServer.new(**server_options(tls: nil, starttls: :optional))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)
    assert lines.any? { |line| line.include?("STARTTLS") }

    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    assert server.tls_reader_used
  end

  def test_starttls_required_blocks_mail_until_encrypted
    tls = FakeTls.new
    start_server(tls: tls, starttls: :required, auth: :disabled)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A530 /, read_smtp_response(socket).to_s)
  end

  def test_openssl_starttls_round_trip_and_cert_hot_swap
    first = OpensslTls.new(self_signed_context(cn: "first.example", serial: 11))
    second = OpensslTls.new(self_signed_context(cn: "second.example", serial: 22))
    server = ReceivingServer.new(**server_options(tls: first, starttls: :optional))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    ssl = ssl_starttls_client(socket)
    assert_equal 11, ssl.peer_cert.serial.to_i
    ssl.print("EHLO secure.example\r\n")
    assert read_smtp_lines(ssl).last.start_with?("250")
    ssl.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(ssl).to_s)
    ssl.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(ssl).to_s)
    ssl.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(ssl).to_s)
    ssl.print("Subject: tls\r\n\r\nbody\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(ssl).to_s)
    ssl.print("QUIT\r\n")
    read_smtp_response(ssl)
    ssl.close

    server.tls = second

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    ssl = ssl_starttls_client(socket)
    assert_equal 22, ssl.peer_cert.serial.to_i
    ssl.close
  end

  def test_handshake_timeout_aborts_starttls
    start_server(tls: SlowTls.new(2), starttls: :optional, handshake_timeout: 0.1)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Server should drop the session after the handshake budget expires.
    wait_until_idle(@servers.last, timeout: 3)
    assert_equal 0, @servers.last.connections_count
  end

  def test_handshake_timeout_applies_when_read_timeout_is_nil
    start_server(
      tls: SlowTls.new(2),
      starttls: :optional,
      read_timeout: nil,
      handshake_timeout: 0.1
    )

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    wait_until_idle(@servers.last, timeout: 3)
    assert_equal 0, @servers.last.connections_count
  end

  def test_write_timeout_during_reply_aborts_with_421
    start_server(tls: BlockingPrintTls.new, starttls: :optional, write_timeout: 0.1, handshake_timeout: 1)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Post-handshake EHLO reply print blocks past write_timeout.
    socket.print("EHLO after.tls\r\n")
    begin
      response = read_smtp_response(socket).to_s
      assert response.start_with?("421 ") || response.empty?
    rescue Errno::ECONNRESET, Errno::EPIPE, IOError, Errno::ECONNABORTED
      # abort path may RST before the 421 is readable
    end
  end

  def test_records_tls_version_and_cipher_after_starttls
    server = TlsRecordingServer.new(**server_options(tls: FakeTls.new, starttls: :optional))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Drive the post-handshake HELO so the server finishes the STARTTLS branch.
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    assert_equal "TLSv1.3", server.tls_version
    assert_equal "TLS_AES_256_GCM_SHA384", server.tls_cipher
    assert server.encrypted
  end

  def test_starttls_discards_pipelined_plaintext_commands
    server = ReceivingServer.new(**server_options(
      tls: FakeTls.new,
      starttls: :optional,
      pipelining: true
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)
    assert lines.any? { |line| line.include?("PIPELINING") }

    # CVE-2011-0411: plaintext pipelined behind STARTTLS must not run after the upgrade.
    socket.print("STARTTLS\r\nMAIL FROM:<evil@attacker.example>\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    readable = IO.select([ socket ], nil, nil, 0.2)
    assert_nil readable, "pipelined MAIL FROM must not produce a reply after STARTTLS"

    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    assert_equal [], server.mail_from_calls
    assert_equal 0, server.receive_count
  end

  def test_starttls_drops_unterminated_plaintext_fragment
    server = ReceivingServer.new(**server_options(
      tls: FakeTls.new,
      starttls: :optional
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    # A MITM can append to the plaintext segment carrying STARTTLS, and a fragment with
    # no terminator slips past the pipelining refusal (CVE-2011-0411).
    socket.print("STARTTLS\r\nMAIL FROM:<injected@example.com>")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Left in place, the fragment would prefix this command and EHLO would come
    # back 503 as a stray MAIL FROM out of sequence.
    socket.print("EHLO test.client.example\r\n")
    assert_match(/\A250/, read_smtp_lines(socket).first.to_s)

    assert_equal [], server.mail_from_calls
  end

  def test_starttls_is_out_of_sequence_inside_a_transaction
    start(ReceivingServer.new(**server_options(
      tls: FakeTls.new,
      starttls: :optional
    )))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<pre@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<everyone@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    # Refusing the command outright is stronger than discarding a pending envelope
    # at the handshake — that way no transaction can straddle it.
    socket.print("STARTTLS\r\n")
    assert_match(/\A503 /, read_smtp_response(socket).to_s)

    # The command was out of sequence, not the connection: clear the
    # transaction and STARTTLS is welcome again.
    socket.print("RSET\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
  end

  def test_starttls_discards_the_pre_tls_greeting
    server = ReceivingServer.new(**server_options(
      tls: FakeTls.new,
      starttls: :optional
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # RFC 3207 §4: everything the client said in the clear is dropped, the
    # greeting included, so no transaction may begin before a fresh EHLO.
    socket.print("MAIL FROM:<post@example.com>\r\n")
    assert_match(/\A503 /, read_smtp_response(socket).to_s)

    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<post@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<postmaster@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: Hi\r\n\r\nBody.\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal 1, server.receive_count
    assert_equal "post@example.com", server.received[:from]
    assert_equal [ "postmaster@example.com" ], server.received[:to]
  end

  def test_tls_accessor_hot_swap_is_visible_to_starttls_advertise
    server = start_server(tls: nil, starttls: :optional)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO before\r\n")
    refute read_smtp_lines(socket).any? { |line| line.include?("STARTTLS") }
    close(socket)

    server.tls = FakeTls.new

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO after\r\n")
    assert read_smtp_lines(socket).any? { |line| line.include?("STARTTLS") }
  end
end
