require_relative "test_helper"

class MailSmtp::RateLimitsTest < MailSmtp::ServerIntegrationTest
  def test_counts_events_per_address_within_a_window
    limiter = MailSmtp::RateLimiter.new

    assert_equal 1, limiter.count("203.0.113.9", now: 0)
    assert_equal 2, limiter.count("203.0.113.9", now: 30)
    assert_equal 1, limiter.count("203.0.113.10", now: 30)
  end

  def test_a_new_window_starts_the_count_over
    limiter = MailSmtp::RateLimiter.new

    limiter.count("203.0.113.9", now: 59)
    assert_equal 1, limiter.count("203.0.113.9", now: 60)
  end

  # One host is normally handed a whole /64, so hopping across it must not reset the count.
  def test_an_ipv6_address_counts_by_its_64
    limiter = MailSmtp::RateLimiter.new

    limiter.count("2001:db8::1", now: 0)
    assert_equal 2, limiter.count("2001:db8::2", now: 0)
    assert_equal 1, limiter.count("2001:db8:0:1::1", now: 0)
  end

  # A dual-stack listener reports IPv4 clients as mapped addresses; the host is the same.
  def test_an_ipv4_mapped_address_counts_as_its_ipv4_host
    limiter = MailSmtp::RateLimiter.new

    limiter.count("::ffff:203.0.113.9", now: 0)
    assert_equal 2, limiter.count("203.0.113.9", now: 0)
    assert_equal 1, limiter.count("::ffff:203.0.113.10", now: 0)
  end

  def test_refuses_mail_from_over_max_messages_per_ip_without_opening_an_envelope
    start_server(max_messages_per_ip: 2)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    2.times do
      socket.print("MAIL FROM:<a@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("RSET\r\n")
      read_smtp_response(socket)
    end

    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A450 4\.7\.1 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A503 /, read_smtp_response(socket).to_s)
  end

  def test_refuses_starttls_over_max_tls_sessions_per_ip_before_any_handshake
    start_server(tls: FakeTls.new, max_tls_sessions_per_ip: 1)

    first = connect(port)
    read_smtp_response(first)
    first.print("EHLO test.client.example\r\n")
    read_smtp_lines(first)
    first.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(first).to_s)

    second = connect(port)
    read_smtp_response(second)
    second.print("EHLO test.client.example\r\n")
    read_smtp_lines(second)
    second.print("STARTTLS\r\n")
    assert_match(/\A454 4\.7\.0 /, read_smtp_response(second).to_s)
    # Still plaintext: the session carries on where a handshake would have broken it.
    second.print("NOOP\r\n")
    assert_match(/\A250 /, read_smtp_response(second).to_s)
  end

  def test_refuses_auth_over_max_auth_attempts_per_ip
    start(AuthedServer.new(**server_options(auth: :required, max_auth_attempts_per_ip: 1, max_auth_failures: nil)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0wrong")}\r\n")
    assert_match(/\A535 /, read_smtp_response(socket).to_s)
    socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0secret")}\r\n")
    assert_match(/\A454 4\.7\.0 /, read_smtp_response(socket).to_s)
  end

  # The base64 lines of an AUTH LOGIN exchange are one attempt, not three.
  def test_auth_continuation_lines_are_not_counted_as_attempts
    start(AuthedServer.new(**server_options(auth: :required, max_auth_attempts_per_ip: 1)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH LOGIN\r\n")
    assert_match(/\A334 /, read_smtp_response(socket).to_s)
    socket.print("#{Base64.strict_encode64("user")}\r\n")
    assert_match(/\A334 /, read_smtp_response(socket).to_s)
    socket.print("#{Base64.strict_encode64("secret")}\r\n")

    assert_match(/\A235 /, read_smtp_response(socket).to_s)
  end

  def test_counts_the_client_named_by_proxy_not_the_proxy
    start_server(proxy_hosts: [ "127.0.0.1" ], max_messages_per_ip: 1)

    first = connect(port)
    read_smtp_response(first)
    first.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\nEHLO test.client.example\r\n")
    read_smtp_lines(first)
    first.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(first).to_s)
    first.print("RSET\r\n")
    read_smtp_response(first)
    first.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A450 /, read_smtp_response(first).to_s)

    second = connect(port)
    read_smtp_response(second)
    second.print("PROXY TCP4 203.0.113.10 10.0.0.1 12345 #{port}\r\nEHLO test.client.example\r\n")
    read_smtp_lines(second)
    second.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(second).to_s)
  end

  def test_rejects_a_per_ip_limit_below_one
    %i[ max_messages_per_ip max_tls_sessions_per_ip max_auth_attempts_per_ip ].each do |option|
      error = assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(option => 0)) }
      assert_match(/#{option} must be nil or an Integer >= 1/, error.message)
    end
  end
end
