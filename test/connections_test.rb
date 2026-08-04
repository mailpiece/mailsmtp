require_relative "test_helper"

class MailSmtp::ConnectionsTest < MailSmtp::ServerIntegrationTest
  def test_accepts_concurrent_connections_up_to_the_per_ip_cap
    start_server(max_connections_per_ip: MAX_PER_IP)

    greetings = Array.new(MAX_PER_IP) { read_smtp_response(connect(port)) }

    assert_equal MAX_PER_IP, greetings.count { |greeting| greeting.to_s.start_with?("220 ") }
  end

  def test_refuses_a_connection_past_the_per_ip_cap_with_a_421
    start_server(max_connections_per_ip: MAX_PER_IP)
    MAX_PER_IP.times { read_smtp_response(connect(port)) }

    assert_match(/\A421 /, read_smtp_response(connect(port)).to_s)
  end

  def test_accepts_a_new_connection_once_the_earlier_ones_have_closed
    server = start_server(max_connections_per_ip: MAX_PER_IP)
    sockets = Array.new(MAX_PER_IP) { connect(port).tap { |socket| read_smtp_response(socket) } }

    sockets.each { |socket| close(socket) }
    wait_until_idle(server)

    assert_match(/\A220 /, read_smtp_response(connect(port)).to_s)
  end

  def test_leaves_connections_uncapped_when_no_per_ip_limit_is_set
    start_server(max_connections_per_ip: nil)

    greetings = Array.new(MAX_PER_IP + 1) { read_smtp_response(connect(port)) }

    assert_equal MAX_PER_IP + 1, greetings.count { |greeting| greeting.to_s.start_with?("220 ") }
  end

  def test_times_out_waiting_for_a_processing_slot
    start_server(max_processings: 1, max_processings_wait: 0.2, max_connections: 10)

    # Hold the single processing slot mid-DATA (after 354, before the body).
    holder = connect(port)
    assert_match(/\A220 /, read_smtp_response(holder).to_s)
    holder.print("EHLO holder.example\r\n")
    read_smtp_lines(holder)
    holder.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(holder).to_s)
    holder.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(holder).to_s)
    holder.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(holder).to_s)

    # Idle / envelope work must not consume a processing slot.
    challenger = connect(port)
    assert_match(/\A220 /, read_smtp_response(challenger).to_s)
    challenger.print("EHLO challenger.example\r\n")
    read_smtp_lines(challenger)
    challenger.print("MAIL FROM:<c@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(challenger).to_s)
    challenger.print("RCPT TO:<d@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(challenger).to_s)

    # The slot is claimed before 354 is sent, so a saturated server answers 421
    # up front instead of inviting a body it can't process yet.
    challenger.print("DATA\r\n")
    assert_match(/\A421 /, read_smtp_response(challenger).to_s)
  end

  def test_closes_a_session_that_exceeds_max_session_duration
    start_server(max_session_duration: 0.3, read_timeout: 30)

    socket = connect(port)
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    sleep 0.4
    socket.print("NOOP\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_idle_timeout_is_not_refreshed_by_protocol_errors
    start_server(read_timeout: 0.35, max_session_duration: 30, max_exceptions: nil)

    socket = connect(port)
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Failed commands must not keep refreshing the idle timer.
    timed_out = false
    10.times do
      socket.print("\r\n")
      response = read_smtp_response(socket).to_s
      if response.start_with?("421 ")
        timed_out = true
        break
      end
      assert_match(/\A500 /, response)
      sleep 0.12
    end

    assert timed_out, "expected a 421 idle timeout after repeated protocol errors"
  end

  def test_closes_after_max_exceptions
    start_server(max_exceptions: 2, max_auth_failures: nil)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    socket.print("NOTACOMMAND\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)
    socket.print("NOTACOMMAND\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # The ceilings a caller gets for free are part of the gem's contract, so drive
  # the shipped numbers rather than assert the constants back to themselves.
  def test_closes_after_the_default_number_of_exceptions
    assert_equal 20, MailSmtp::Server::MAX_EXCEPTIONS

    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    MailSmtp::Server::MAX_EXCEPTIONS.times do
      socket.print("NOTACOMMAND\r\n")
      assert_match(/\A500 /, read_smtp_response(socket).to_s)
    end

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # Well under MAX_EXCEPTIONS, so the AUTH ceiling is what fires here.
  def test_closes_after_the_default_number_of_auth_failures
    assert_equal 3, MailSmtp::Server::MAX_AUTH_FAILURES

    start(AuthedServer.new(**server_options(auth: :required)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    MailSmtp::Server::MAX_AUTH_FAILURES.times do
      socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0wrong")}\r\n")
      assert_match(/\A535 /, read_smtp_response(socket).to_s)
    end

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_capped_connection_does_not_call_disconnected_without_connected
    server = LifecycleServer.new(**server_options(max_connections: 1))
    start(server)
    connected_before = server.connected_count
    disconnected_before = server.disconnected_count

    holder = connect(port)
    assert_match(/\A220 /, read_smtp_response(holder).to_s)
    assert_equal connected_before + 1, server.connected_count

    refused = connect(port)
    assert_match(/\A421 /, read_smtp_response(refused).to_s)
    sleep 0.05

    assert_equal connected_before + 1, server.connected_count
    assert_equal disconnected_before, server.disconnected_count
  ensure
    close(holder) if holder
  end

  # The refusal is answered by the acceptor itself. Nothing a connection thread would
  # have done runs, starting with building the session — spending a thread to say no
  # is what turns a connection flood into a thread flood.
  def test_a_refused_connection_never_reaches_a_connection_thread
    server = SessionCountingServer.new(**server_options(max_connections: 1))
    start(server)

    holder = connect(port)
    assert_match(/\A220 /, read_smtp_response(holder).to_s)

    refused = connect(port)
    assert_match(/\A421 /, read_smtp_response(refused).to_s)
    assert_nil refused.gets, "a refused connection is closed behind its 421"

    assert_equal 1, server.built_sessions
  ensure
    close(holder) if holder
  end

  # Descriptor exhaustion is transient — it clears as connections close — so the
  # listener waits it out. Giving up would leave the process alive and healthy-looking
  # with nothing answering the port.
  def test_keeps_listening_through_a_burst_of_accept_failures
    listener = bind_listener
    server = start(MailSmtp::Server.new(**server_options(
      listeners: [ FailingListener.new(listener, error: Errno::EMFILE, failures: 11) ],
      logger: Logger.new(IO::NULL))))

    assert_match(/\A220 /, read_smtp_response(connect(port_of(listener))).to_s)
    assert_equal false, server.stopped?
  end

  # The counterpart: a listener that is itself broken is not something to wait out.
  def test_stops_accepting_when_the_listener_itself_fails
    listener = bind_listener
    server = start(MailSmtp::Server.new(**server_options(
      listeners: [ FailingListener.new(listener, error: Errno::EBADF, failures: 1) ],
      logger: Logger.new(IO::NULL))))

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.01 until server.stopped? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

    assert server.stopped?, "an unrecoverable accept error must not be retried"
  end
end
