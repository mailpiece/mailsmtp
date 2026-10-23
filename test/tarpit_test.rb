require_relative "test_helper"

class MailSmtp::TarpitTest < MailSmtp::ServerIntegrationTest
  def test_delays_error_replies_once_a_session_is_past_error_sleep_after
    start_server(error_sleep_after: 2, error_sleep_time: 0.3, max_exceptions: nil)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    2.times do
      assert_operator seconds_to_reply(socket, "NOTACOMMAND\r\n"), :<, 0.25
    end

    assert_operator seconds_to_reply(socket, "NOTACOMMAND\r\n"), :>=, 0.3
  end

  def test_does_not_delay_a_successful_reply
    start_server(error_sleep_after: 1, error_sleep_time: 0.3, max_exceptions: nil)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("NOTACOMMAND\r\n")
    read_smtp_response(socket)
    socket.print("NOTACOMMAND\r\n")
    read_smtp_response(socket)

    assert_operator seconds_to_reply(socket, "NOOP\r\n"), :<, 0.25
  end

  # Once stressed, the one-error budget ends the session; there is nothing left to slow down.
  def test_does_not_delay_while_stressed
    server = start_server(max_connections: 2, stress_threshold: 0.8, error_sleep_after: 2, error_sleep_time: 1, max_exceptions: nil)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    2.times do
      socket.print("NOTACOMMAND\r\n")
      read_smtp_response(socket)
    end

    read_smtp_response(connect(port))
    assert_predicate server, :stressed?

    assert_operator seconds_to_reply(socket, "NOTACOMMAND\r\n"), :<, 0.25
    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_error_sleep_after_below_one
    error = assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(error_sleep_after: 0)) }

    assert_match(/error_sleep_after must be nil or an Integer >= 1/, error.message)
  end

  def test_rejects_a_negative_or_non_numeric_error_sleep_time
    [ -1, "1" ].each do |value|
      error = assert_raises(ArgumentError) { MailSmtp::Server.new(**server_options(error_sleep_time: value)) }
      assert_match(/error_sleep_time must be a Numeric >= 0/, error.message)
    end
  end

  private
    def seconds_to_reply(socket, command)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      socket.print(command)
      read_smtp_response(socket)
      Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    end
end
