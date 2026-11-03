require_relative "test_helper"

# StringIO for injectable logger tests
require "stringio"

class MailSmtp::LoggingTest < MailSmtp::ServerIntegrationTest
  def test_injectable_logger_includes_remote_ip
    io = StringIO.new
    logger = Logger.new(io)
    logger.level = Logger::DEBUG
    start_server(logger: logger)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("NOOP\r\n")
    read_smtp_response(socket)

    assert_includes io.string, "127.0.0.1"
    assert_match(/NOOP|>>>|<<</, io.string)
  end

  # A mid-body disconnect must log as DEBUG, not as an ERROR with a doomed 421 write.
  def test_logs_a_mid_data_hang_up_as_a_disconnect_not_an_error
    log_io = StringIO.new
    logger = Logger.new(log_io)
    logger.level = Logger::DEBUG
    logger.formatter = proc { |severity, _time, _progname, msg| "[#{severity}] #{msg}\n" }
    start_server(logger: logger)

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
    socket.print("partial body, no terminating dot\r\n")
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack("ii"))
    socket.close
    wait_until_idle(@servers.last)

    logged = log_io.string
    assert_match(/\[DEBUG\].*Client hung up/, logged)
    refute_match(/\[ERROR\]/, logged)
    refute_match(/421/, logged)
  end

  # Postfix logs what a client brings on itself at INFO; ERROR is for our own failures.
  def test_logs_a_refused_command_at_info
    start_server(logger: severity_logger)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("BOGUS\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*CommandNotRecognized/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_pipelined_command_at_info
    start_server(logger: severity_logger)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("NOOP\r\nNOOP\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*PipeliningNotSupported/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_policy_refusal_from_a_hook_at_info
    start(PolicyServer.new(**server_options(logger: severity_logger)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("HELO test.client.example\r\n")
    read_smtp_response(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*RelayDenied/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_policy_refusal_from_receive_at_info
    server = Class.new(ReceivingServer) do
      define_method(:receive) do |_session, io|
        io.read
        raise RelayDenied
      end
    end
    start(server.new(**server_options(logger: severity_logger)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("HELO test.client.example\r\n")
    read_smtp_response(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("RCPT TO:<b@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("DATA\r\n")
    read_smtp_response(socket)
    socket.print("Subject: Hi\r\n\r\nBody\r\n.\r\n")
    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*RelayDenied/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_an_unexpected_error_from_a_hook_at_error
    server = Class.new(ReceivingServer) do
      define_method(:mail_from) { |_session, _address| raise "database is down" }
    end
    start(server.new(**server_options(logger: severity_logger)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("HELO test.client.example\r\n")
    read_smtp_response(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A451 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[ERROR\].*database is down \(RuntimeError\)/, logged)
  end

  def test_logs_an_unexpected_error_from_receive_at_error
    server = Class.new(ReceivingServer) do
      define_method(:receive) { |_session, _io| raise "disk is full" }
    end
    start(server.new(**server_options(logger: severity_logger)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("HELO test.client.example\r\n")
    read_smtp_response(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("RCPT TO:<b@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("DATA\r\n")
    read_smtp_response(socket)
    socket.print("Subject: Hi\r\n\r\nBody\r\n.\r\n")
    assert_match(/\A451 /, read_smtp_response(socket).to_s)
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_match(/\[ERROR\].*disk is full \(RuntimeError\)/, logged)
  end

  def test_logs_a_tarpitted_refusal_at_info
    start_server(logger: severity_logger, error_sleep_after: 1, error_sleep_time: 0.01, max_exceptions: nil)

    socket = connect(port)
    read_smtp_response(socket)
    2.times do
      socket.print("BOGUS\r\n")
      assert_match(/\A500 /, read_smtp_response(socket).to_s)
    end
    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    assert_equal 2, logged.scan(/\[INFO\].*CommandNotRecognized/).size
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_the_error_limit_at_info
    start_server(logger: severity_logger, max_exceptions: 2)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("BOGUS\r\n")
    read_smtp_response(socket)
    socket.print("BOGUS\r\n")
    read_smtp_response(socket)
    assert_match(/\A421 /, read_smtp_response(socket).to_s)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*Too many protocol errors \(MailSmtp::ServiceUnavailable\)/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_read_timeout_at_info
    start_server(logger: severity_logger, read_timeout: 0.2)

    socket = connect(port)
    read_smtp_response(socket)
    assert_match(/\A421 /, read_smtp_response(socket).to_s)
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*Read timed out \(MailSmtp::ServiceUnavailable\)/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_failed_starttls_handshake_at_info
    start_server(logger: severity_logger, tls: OpensslTls.new(self_signed_context))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    socket.print("not a TLS ClientHello\r\n")
    wait_until_idle(@servers.last)

    assert_match(/\[INFO\].*\(OpenSSL::SSL::SSLError\)/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  # The client drops TCP without a TLS close_notify: "SSL_read: unexpected eof".
  def test_logs_a_tls_session_cut_short_below_error
    start_server(logger: severity_logger, tls: OpensslTls.new(self_signed_context))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    read_smtp_response(socket)
    ssl = ssl_starttls_client(socket)
    ssl.print("EHLO secure.example\r\n")
    read_smtp_lines(ssl)
    socket.close
    wait_until_idle(@servers.last)

    refute_match(/\[ERROR\]/, logged)
  end

  # A server out of capacity is ours to fix, so it stands out above the refusals.
  def test_logs_no_free_processing_slot_at_warn
    start_server(logger: severity_logger, max_processings: 1, max_processings_wait: 0.2, max_connections: 10)

    holder, challenger = Array.new(2) do
      connect(port).tap do |socket|
        read_smtp_response(socket)
        socket.print("HELO test.client.example\r\n")
        read_smtp_response(socket)
        socket.print("MAIL FROM:<a@example.com>\r\n")
        read_smtp_response(socket)
        socket.print("RCPT TO:<b@example.com>\r\n")
        read_smtp_response(socket)
      end
    end
    holder.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(holder).to_s)
    challenger.print("DATA\r\n")
    assert_equal "421 4.3.2 Service not available, closing transmission channel", read_smtp_response(challenger).to_s.chomp

    assert_match(/\[WARN\].*no processing slot free within 0.2s \(MailSmtp::ServerBusy\)/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  # The acceptor answers the global cap first; this is the backstop behind it.
  def test_logs_a_drop_at_max_connections_at_warn
    server = Class.new(ReceivingServer) do
      define_method(:claim_admission) { true }
      define_method(:release_admission) { }
    end
    start(server.new(**server_options(logger: severity_logger, max_connections: 1)))
    read_smtp_response(connect(port))

    assert_match(/\A421 /, read_smtp_response(connect(port)).to_s)

    assert_match(/\[WARN\].*max_connections \(1\) reached \(MailSmtp::ServerBusy\)/, logged)
    refute_match(/\[ERROR\]/, logged)
  end

  def test_logs_a_drop_past_the_per_ip_cap_at_info
    start_server(logger: severity_logger, max_connections_per_ip: MAX_PER_IP)
    MAX_PER_IP.times { read_smtp_response(connect(port)) }

    assert_match(/\A421 /, read_smtp_response(connect(port)).to_s)

    assert_match(/\[INFO\].*Too many connections from 127.0.0.1 \(MailSmtp::ServiceUnavailable\)/, logged)
    refute_match(/\[WARN\]|\[ERROR\]/, logged)
  end

  # Code that rescues ServiceUnavailable still catches the server being busy.
  def test_server_busy_is_a_service_unavailable
    assert_operator MailSmtp::ServerBusy, :<, MailSmtp::ServiceUnavailable
    assert_equal MailSmtp::ServiceUnavailable.new.response, MailSmtp::ServerBusy.new.response
  end

  private
    def severity_logger
      @log_io = StringIO.new
      Logger.new(@log_io).tap do |logger|
        logger.level = Logger::DEBUG
        logger.formatter = proc { |severity, _time, _progname, msg| "[#{severity}] #{msg}\n" }
      end
    end

    def logged
      @log_io.string
    end
end
