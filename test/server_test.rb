require_relative "test_helper"

class MailSmtp::ServerTest < MailSmtp::ServerIntegrationTest
  def test_has_a_version_number
    assert_match(/\A\d+\.\d+\.\d+\z/, MailSmtp::VERSION)
  end

  def test_receives_a_message_through_net_smtp
    server = ReceivingServer.new(**server_options)
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nBody.\r\n",
        "a@example.com", "b@example.com")
    end

    assert_equal "a@example.com", server.received[:from]
    assert_equal [ "b@example.com" ], server.received[:to]
    assert_includes server.received[:data], "Subject: Hi"
  end

  # These three refusals are the silent ones: accepting the combination leaves a
  # server that boots and then misbehaves, rather than one that fails loudly.
  def test_smtputf8_without_eight_bit_mime_is_refused
    error = assert_raises(ArgumentError) do
      ReceivingServer.new(**server_options(smtputf8: true, eight_bit_mime: false))
    end
    assert_match(/RFC 6531/, error.message)
  end

  def test_starttls_required_without_a_tls_object_is_refused
    error = assert_raises(ArgumentError) do
      ReceivingServer.new(**server_options(starttls: :required))
    end
    assert_match(/requires a tls object/, error.message)
  end

  def test_max_recipients_below_the_rfc_floor_is_refused
    error = assert_raises(ArgumentError) do
      ReceivingServer.new(**server_options(max_recipients: 99))
    end
    assert_match(/RFC 5321/, error.message)
  end

  def test_logger_severity_combined_with_logger_is_refused
    error = assert_raises(ArgumentError) do
      ReceivingServer.new(**server_options(logger: Logger.new(IO::NULL), logger_severity: Logger::FATAL))
    end
    assert_match(/cannot be combined/, error.message)
  end

  def test_build_session_hook_supplies_a_custom_session
    server = CustomSessionServer.new(**server_options)
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\n\r\nHi\r\n",
        "a@example.com", "b@example.com")
    end

    assert server.used_custom_session
  end
end
