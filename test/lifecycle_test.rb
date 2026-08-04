require_relative "test_helper"

class MailSmtp::LifecycleTest < MailSmtp::ServerIntegrationTest
  def test_listens_on_multiple_ports
    listener_a = bind_listener
    listener_b = bind_listener
    port_a = port_of(listener_a)
    port_b = port_of(listener_b)
    start(MailSmtp::Server.new(**server_options(listeners: [ listener_a, listener_b ])))

    assert_match(/\A220 /, read_smtp_response(connect(port_a)).to_s)
    assert_match(/\A220 /, read_smtp_response(connect(port_b)).to_s)
  end

  # Ports arrive as ENV strings, where a zero-padded one is still decimal —
  # read as octal, "02525" would quietly bind 1365.
  def test_reads_a_zero_padded_listen_port_as_decimal
    server = MailSmtp::Server.new(**server_options(port: "02525"))

    assert_equal [ "127.0.0.1:2525" ], server.addresses
  end

  def test_rejects_a_listen_port_outside_the_tcp_range
    assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(port: "70000")) }
    assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(port: "0")) }
  end

  def test_rejects_max_recipients_below_rfc_minimum
    assert_raises(ArgumentError) do
      MailSmtp::Server.new(**server_options(max_recipients: 99))
    end
  end

  def test_rejects_zero_max_connections
    assert_raises(ArgumentError) do
      MailSmtp::Server.new(**server_options(max_connections: 0))
    end
  end

  def test_requires_tls_object_when_starttls_is_required
    assert_raises(ArgumentError) do
      MailSmtp::Server.new(**server_options(starttls: :required, tls: nil))
    end
  end

  # RFC 6531 §3.1: advertising SMTPUTF8 alone would earn a 501 for the BODY=8BITMIME
  # that an internationalized message carries, so it fails at boot instead.
  def test_rejects_smtputf8_without_eight_bit_mime
    assert_raises(ArgumentError) do
      MailSmtp::Server.new(**server_options(smtputf8: true, eight_bit_mime: false))
    end

    MailSmtp::Server.new(**server_options(smtputf8: true, eight_bit_mime: true))
  end

  def test_stop_immediately_after_start
    server = start_server
    server.stop(drain_for: 0)

    assert_predicate server, :stopped?
    assert_raises(Errno::ECONNREFUSED) { TCPSocket.new("127.0.0.1", port) }
  end

  def test_forced_stop_aborts_with_linger_reset
    server = start_server
    socket = connect(port)
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    server.stop(drain_for: 0)

    # After RST/abort the peer should see a hard close rather than a clean 221.
    begin
      socket.print("NOOP\r\n")
      response = read_smtp_response(socket)
      assert_nil response
    rescue Errno::ECONNRESET, Errno::EPIPE, Errno::ECONNABORTED, IOError
      # expected on RST
    end
  end

  # A forced stop is not the current command failing. Answering it with a 451
  # and carrying on would run everything the client pipelined behind it.
  def test_forced_stop_does_not_run_commands_pipelined_behind_it
    server = SlowCommandServer.new(**server_options(pipelining: true))
    start(server)
    socket = connect(port)
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    socket.print("NOOP\r\n" * 5)
    sleep 0.2
    elapsed = time_spent { server.stop(drain_for: 0) }

    assert_equal 1, server.process_line_calls
    assert_operator elapsed, :<, SlowCommandServer::COMMAND_SECONDS * 3
  end

  # Exactly one StopConnection is delivered per straggler, so a session that
  # swallows it must be abandoned rather than left holding shutdown open.
  def test_forced_stop_abandons_a_connection_that_ignores_it
    server = UnstoppableServer.new(**server_options)
    start(server)
    socket = connect(port)
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    socket.print("NOOP\r\n")
    sleep 0.2
    elapsed = time_spent { server.stop(drain_for: 0) }

    assert_predicate server, :stopped?
    assert_operator elapsed, :<, UnstoppableServer::IGNORED_STOP_SECONDS
  end

  private
    def time_spent
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      yield
      Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    end
end
