require_relative "test_helper"

class MailSmtp::CommandsTest < MailSmtp::ServerIntegrationTest
  def test_ehlo_requires_an_argument
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  # RFC 2034 excludes the greeting and the HELO/EHLO answer, where an RFC 821 client
  # reads the server domain out of the reply and would otherwise read "2.0.0".
  def test_a_helo_reply_carries_no_enhanced_status_code
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("HELO test.client.example\r\n")
    response = read_smtp_response(socket).to_s

    assert_match(/\A250 /, response)
    refute_match(/\A250 \d\.\d\.\d/, response)
  end

  def test_second_ehlo_resets_like_rset
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO first.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    socket.print("EHLO second.example\r\n")
    lines = read_smtp_lines(socket)
    assert_equal "250 OK", lines.last.strip

    socket.print("MAIL FROM:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_noop_accepts_an_optional_string
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("NOOP keep-alive\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_rset_before_helo_returns_250
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("RSET\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_ehlo_advertises_size_and_not_starttls_without_a_tls_object
    start_server(max_message_size: 1024)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)

    assert lines.any? { |line| line.start_with?("250-SIZE 1024") }
    assert lines.any? { |line| line.include?("ENHANCEDSTATUSCODES") }
    refute lines.any? { |line| line.include?("STARTTLS") }
    refute lines.any? { |line| line.include?("AUTH") }
  end

  def test_ehlo_advertises_smtputf8_and_8bitmime_when_enabled
    start_server(eight_bit_mime: true, smtputf8: true)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)

    assert lines.any? { |line| line.include?("8BITMIME") }
    assert lines.any? { |line| line.include?("SMTPUTF8") }
  end

  def test_replies_include_enhanced_status_codes
    start_server

    socket = connect(port)
    greeting = read_smtp_response(socket).to_s
    assert_match(/\A220 /, greeting)
    refute_match(/\A220 \d\.\d\.\d /, greeting)

    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)
    assert_equal "250 OK", lines.last.strip

    socket.print("NOOP\r\n")
    assert_match(/\A250 2\.0\.0 /, read_smtp_response(socket).to_s)

    socket.print("VRFY someone@example.com\r\n")
    assert_match(/\A252 2\.5\.0 /, read_smtp_response(socket).to_s)

    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 2\.0\.0 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A503 5\.5\.1 /, read_smtp_response(socket).to_s)
  end

  def test_vrfy_returns_252_and_expn_help_return_502
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    socket.print("VRFY someone@example.com\r\n")
    assert_match(/\A252 /, read_smtp_response(socket).to_s)

    socket.print("EXPN list\r\n")
    assert_match(/\A502 /, read_smtp_response(socket).to_s)

    socket.print("HELP\r\n")
    assert_match(/\A502 /, read_smtp_response(socket).to_s)
  end

  def test_refuses_a_pipelined_second_command
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    # Both lines arrive in one read, so the first command itself is refused — we never
    # advertise PIPELINING, and a second buffered command already broke that contract.
    socket.print("EHLO test.client.example\r\nNOOP\r\n")

    assert_match(/\A500 /, read_smtp_response(socket).to_s)
  end

  def test_allows_pipelined_commands_when_enabled
    start_server(pipelining: true)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)
    assert lines.any? { |line| line.include?("PIPELINING") }

    socket.print("NOOP\r\nRSET\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_oversized_command_lines
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO #{"x" * 600}\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_drops_the_connection_on_a_cross_protocol_http_request
    start_server

    %w[ GET POST CONNECT ].each do |verb|
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("#{verb} / HTTP/1.1\r\n")

      assert_match(/\A502 /, read_smtp_response(socket).to_s, "#{verb} should be refused")
      # No 221, and nothing further to read: the session is over.
      assert_nil socket.gets, "#{verb} should close the connection"
    end
  end

  def test_process_line_nil_does_not_emit_local_error
    start(NilProcessLineServer.new(**server_options))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("NOOP\r\n")
    # Give the silent NOOP a turn so EHLO is not treated as pipelined.
    sleep 0.05
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)

    refute lines.any? { |line| line.start_with?("451") }
    assert lines.last.start_with?("250")
  end

  def test_app_defined_error_renders_status_in_reply
    start(PolicyServer.new(**server_options))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_equal "550 5.7.1 Relay denied\r\n", read_smtp_response(socket)
  end
end
