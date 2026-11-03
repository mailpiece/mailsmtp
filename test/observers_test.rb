require_relative "test_helper"

class MailSmtp::ObserversTest < MailSmtp::ServerIntegrationTest
  # Records every observer call without the session, from whichever thread makes it.
  class ObservingServer < ReceivingServer
    def initialize(**)
      super
      @observed = []
      @observed_mutex = Mutex.new
    end

    def observed
      @observed_mutex.synchronize { @observed.dup }
    end

    def connection_refused(remote_ip, limit)
      record(:connection_refused, remote_ip, limit)
    end

    def error_slept(_session, seconds)
      record(:error_slept, seconds)
    end

    def error_limit_reached(_session)
      record(:error_limit_reached)
    end

    def replied(_session, code)
      record(:replied, code)
    end

    private
      def record(*call)
        @observed_mutex.synchronize { @observed << call }
      end
  end

  class FailingObserverServer < ReceivingServer
    def connection_refused(_remote_ip, _limit) = raise("connection_refused failed")
    def error_slept(_session, _seconds) = raise("error_slept failed")
    def error_limit_reached(_session) = raise("error_limit_reached failed")
    def replied(_session, _code) = raise("replied failed")
  end

  def test_connection_refused_at_max_connections
    server = start(ObservingServer.new(**server_options(max_connections: 1)))
    holder = connect(port)
    read_smtp_response(holder)

    assert_match(/\A421 /, read_smtp_response(connect(port)).to_s)

    assert_equal [ [ :connection_refused, "127.0.0.1", :max_connections ] ], wait_for_refusals(server)
  end

  def test_connection_refused_at_max_connections_per_ip
    server = start(ObservingServer.new(**server_options(max_connections_per_ip: MAX_PER_IP)))
    MAX_PER_IP.times { read_smtp_response(connect(port)) }

    assert_match(/\A421 /, read_smtp_response(connect(port)).to_s)

    assert_equal [ [ :connection_refused, "127.0.0.1", :max_connections_per_ip ] ], wait_for_refusals(server)
  end

  def test_error_slept_after_each_tarpitted_error
    server = start(ObservingServer.new(**server_options(error_sleep_after: 1, error_sleep_time: 0.01, max_exceptions: nil)))
    socket = greeted_socket

    3.times do
      socket.print("NOTACOMMAND\r\n")
      read_smtp_response(socket)
    end

    assert_equal [ [ :error_slept, 0.01 ] ] * 2, server.observed.select { |call| call.first == :error_slept }
  end

  def test_error_limit_reached_once_max_exceptions_ends_the_session
    server = start(ObservingServer.new(**server_options(max_exceptions: 2)))
    socket = greeted_socket

    socket.print("NOTACOMMAND\r\n")
    read_smtp_response(socket)
    assert_empty server.observed.select { |call| call.first == :error_limit_reached }

    socket.print("NOTACOMMAND\r\n")
    read_smtp_response(socket)

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
    assert_equal [ [ :error_limit_reached ] ], server.observed.select { |call| call.first == :error_limit_reached }
  end

  def test_replied_with_every_code_sent_including_the_closing_421
    server = start(ObservingServer.new(**server_options(max_exceptions: 1)))
    socket = greeted_socket
    socket.print("NOTACOMMAND\r\n")
    read_smtp_response(socket)
    read_smtp_response(socket)
    assert_nil socket.gets
    wait_until_idle(server)

    assert_equal [ 220, 250, 500, 421 ], server.observed.filter_map { |hook, code| code if hook == :replied }
  end

  def test_a_failing_observer_is_logged_and_the_session_carries_on
    log = StringIO.new
    start(FailingObserverServer.new(**server_options(error_sleep_after: 1, error_sleep_time: 0.01,
      max_exceptions: 3, logger: Logger.new(log))))
    socket = greeted_socket

    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    3.times do
      socket.print("NOTACOMMAND\r\n")
      assert_match(/\A500 /, read_smtp_response(socket).to_s)
    end
    assert_match(/\A421 /, read_smtp_response(socket).to_s)

    assert_includes log.string, "replied failed"
    assert_includes log.string, "error_slept failed"
    assert_includes log.string, "error_limit_reached failed"
  end

  def test_a_failing_observer_does_not_stop_the_acceptor
    log = StringIO.new
    server = start(FailingObserverServer.new(**server_options(max_connections: 1, logger: Logger.new(log))))
    holder = connect(port)
    read_smtp_response(holder)

    refused = connect(port)
    assert_match(/\A421 /, read_smtp_response(refused).to_s)
    assert_nil refused.gets
    close(holder)
    wait_until_idle(server)

    assert_match(/\A220 /, read_smtp_response(connect(port)).to_s)
    assert_equal false, server.stopped?
    assert_includes log.string, "connection_refused failed"
  end

  private
    def greeted_socket
      connect(port).tap do |socket|
        read_smtp_response(socket)
        socket.print("EHLO test.client.example\r\n")
        read_smtp_lines(socket)
      end
    end

    # The acceptor reports a refusal after it has closed the socket.
    def wait_for_refusals(server, timeout: 2)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      loop do
        refusals = server.observed.select { |call| call.first == :connection_refused }
        return refusals if refusals.any? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep 0.01
      end
    end
end
