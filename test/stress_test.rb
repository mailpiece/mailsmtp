require_relative "test_helper"

class MailSmtp::StressTest < MailSmtp::ServerIntegrationTest
  def test_stressed_once_admissions_reach_the_threshold_share_of_max_connections
    server = start_server(max_connections: 5, stress_threshold: 0.8)

    sockets = Array.new(3) { connect(port).tap { |socket| read_smtp_response(socket) } }
    refute_predicate server, :stressed?

    sockets << connect(port).tap { |socket| read_smtp_response(socket) }
    assert_predicate server, :stressed?

    close(sockets.pop)
    wait_until_not_stressed(server)
    refute_predicate server, :stressed?
  end

  def test_never_stressed_without_a_threshold
    server = start_server(max_connections: 2)

    read_smtp_response(connect(port))
    read_smtp_response(connect(port))

    refute_predicate server, :stressed?
  end

  def test_rejects_a_threshold_outside_zero_to_one
    [ 0.0, 1.5, 1 ].each do |threshold|
      error = assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(stress_threshold: threshold)) }
      assert_match(/stress_threshold must be nil or a Float above 0 and at most 1/, error.message)
    end
  end

  def test_a_stressed_server_closes_after_one_protocol_error
    server = start_server(max_connections: 2, stress_threshold: 0.8, max_exceptions: 20)

    socket = connect(port)
    read_smtp_response(socket)
    read_smtp_response(connect(port))
    assert_predicate server, :stressed?

    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("NOTACOMMAND\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # Ten seconds is too long to wait out in a test, so the guard is asked directly
  # with an idle start that is past the stressed timeout but inside the configured one.
  def test_a_stressed_server_shortens_the_idle_timeout_to_ten_seconds
    assert_equal 10, MailSmtp::Server::STRESS_TIMEOUT

    server = start_server(max_connections: 2, stress_threshold: 0.8, read_timeout: 300)
    idle_since = server.send(:monotonic_time) - 11
    server.send(:raise_if_idle_timeout, idle_since)

    read_smtp_response(connect(port))
    read_smtp_response(connect(port))
    assert_predicate server, :stressed?

    assert_raises(MailSmtp::ServiceUnavailable) { server.send(:raise_if_idle_timeout, idle_since) }
  end

  def test_a_configured_handshake_timeout_below_ten_seconds_stays_in_force_under_stress
    server = start_server(max_connections: 2, stress_threshold: 0.8, handshake_timeout: 0.1, tls: SlowTls.new(2))

    socket = connect(port)
    read_smtp_response(socket)
    read_smtp_response(connect(port))
    assert_predicate server, :stressed?

    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # Timed, because the stressed idle timeout would also end in a 421, ten seconds on.
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_match(/\A421 /, read_smtp_response(socket).to_s)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
  end

  private
    def wait_until_not_stressed(server, timeout: 5)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

      sleep 0.01 while server.stressed? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    end
end
