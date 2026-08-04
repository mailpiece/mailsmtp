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
end
