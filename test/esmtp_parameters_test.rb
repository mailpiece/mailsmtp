require_relative "test_helper"
require "stringio"

class MailSmtp::EsmtpParametersTest < MailSmtp::ServerIntegrationTest
  # RFC 4954 §5: what the client asserts about who is sending, recorded for the
  # application to audit and trusted for nothing.
  class AuthIdentityServer < AuthedServer
    attr_reader :seen_auth_identity

    def mail_from(session, address)
      @seen_auth_identity = session.envelope.auth_identity
      super
    end
  end

  # A refusal that is the application's rather than the engine's: by the time +mail_from+
  # is called the parameters are on the envelope, so a raise here is the unseen path.
  class SenderRefused < MailSmtp::Error
    status 550, "Sender refused", enhanced: "5.7.1"
  end

  class RefusingSenderServer < ReceivingServer
    REFUSED_SENDER = "refused@example.com"

    attr_reader :seen_declared_size

    def mail_from(session, address)
      @seen_declared_size = session.envelope.declared_size
      raise SenderRefused if address == REFUSED_SENDER
      super
    end
  end

  def test_accepts_smtputf8_mail_from_when_enabled
    server = ReceivingServer.new(**server_options(smtputf8: true, eight_bit_mime: true))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> BODY=8BITMIME SMTPUTF8\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: Hi\r\n\r\nBody\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal :eight_bit_mime, server.last_body_encoding
    assert_equal true, server.last_smtputf8
  end

  def test_rejects_mail_from_when_declared_size_exceeds_limit
    io = StringIO.new
    logger = Logger.new(io)
    logger.level = Logger::ERROR
    start_server(max_message_size: 100, logger: logger)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> SIZE=200\r\n")

    assert_match(/\A552 /, read_smtp_response(socket).to_s)
    assert_match(/Declared 200 bytes, limit is 100/, io.string)
  end

  # A zero-padded SIZE is decimal; Integer("08") would otherwise raise and "020000" would read as octal.
  def test_reads_a_zero_padded_declared_size_as_decimal
    start_server(max_message_size: 10_000)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> SIZE=08\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_a_zero_padded_declared_size_over_the_limit
    start_server(max_message_size: 10_000)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    # Decimal 20000 exceeds the limit; octal 020000 would be 8192 and pass.
    socket.print("MAIL FROM:<a@example.com> SIZE=020000\r\n")

    assert_match(/\A552 /, read_smtp_response(socket).to_s)
  end

  def test_stores_declared_size_on_envelope_when_under_limit
    server = DeclaredSizeServer.new(**server_options(max_message_size: 10_000))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> SIZE=500\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nbody\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal 500, server.seen_declared_size
  end

  def test_does_not_treat_size_equals_in_local_part_as_size_parameter
    # Under limit 100, a false-positive parse of local-part "size=2048" would 552.
    server = DeclaredSizeServer.new(**server_options(max_message_size: 100))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<size=2048@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nbody\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_nil server.seen_declared_size
    assert_equal "size=2048@example.com", server.received[:from]
  end

  def test_records_the_asserted_auth_identity_from_mail_from
    server = AuthIdentityServer.new(**server_options(auth: :required))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=user@example.com\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "user@example.com", server.seen_auth_identity
  end

  # "<>" asserts no identity at all, which must not read as a mailbox — and an
  # absent AUTH= must not read as an assertion.
  def test_records_the_no_identity_auth_form_as_an_empty_identity
    server = AuthIdentityServer.new(**server_options(auth: :required))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=<>\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "", server.seen_auth_identity
  end

  def test_leaves_the_auth_identity_unset_without_the_parameter
    server = AuthIdentityServer.new(**server_options(auth: :required))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_nil server.seen_auth_identity
  end

  def test_decodes_an_xtext_escaped_auth_identity
    server = AuthIdentityServer.new(**server_options(auth: :required))
    start(server)

    socket = authenticated_connection(port)
    # "+3D" is "=", "+2B" is "+" — neither may appear raw in xtext.
    socket.print("MAIL FROM:<a@example.com> AUTH=e+3Dmc+2B2@example.com\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "e=mc+2@example.com", server.seen_auth_identity
  end

  def test_rejects_a_malformed_xtext_auth_identity
    start(AuthedServer.new(**server_options(auth: :required)))

    socket = authenticated_connection(port)
    # "+ZZ" is not a hex escape, and a bare "=" is outside the xtext alphabet.
    socket.print("MAIL FROM:<a@example.com> AUTH=user+ZZ@example.com\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com> AUTH=e=mc2@example.com\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com> AUTH=\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  # An escaped control character is exactly how header forgery would slip past
  # the command grammar, which strips CR and LF before the line is ever parsed.
  def test_rejects_an_auth_identity_that_decodes_to_a_control_character
    start(AuthedServer.new(**server_options(auth: :required)))

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=user+0D+0AInjected:+20yes\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com> AUTH=user+00@example.com\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  # Without SMTPUTF8 the engine promises the application ASCII envelope strings,
  # and an escape must not be a way around that promise.
  def test_rejects_a_non_ascii_auth_identity_without_smtputf8
    start(AuthedServer.new(**server_options(auth: :required)))

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=user+FF@example.com\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_decodes_a_utf8_auth_identity_under_smtputf8
    server = AuthIdentityServer.new(**server_options(auth: :required, smtputf8: true, eight_bit_mime: true))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=us+C3+A9r@example.com SMTPUTF8\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "usér@example.com", server.seen_auth_identity
    assert_equal Encoding::UTF_8, server.seen_auth_identity.encoding
  end

  def test_accepts_auth_alongside_the_other_mail_from_parameters
    server = AuthIdentityServer.new(**server_options(
      auth: :required, eight_bit_mime: true, max_message_size: 10_000
    ))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> SIZE=500 AUTH=user@example.com BODY=8BITMIME\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal "user@example.com", server.seen_auth_identity
    refute_match(/AUTH=/i, server.mail_from_calls.first.to_s)
  end

  # Every parameter but AUTH= is still unknown, and stripping AUTH= must not
  # smuggle its neighbours past the 555.
  def test_still_rejects_an_unknown_parameter_next_to_auth
    start(AuthedServer.new(**server_options(auth: :required)))

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=user@example.com FOO=bar\r\n")

    assert_match(/\A555 /, read_smtp_response(socket).to_s)
  end

  # With AUTH disabled the extension was never advertised, so the parameter is
  # refused like any other whose extension is off — not quietly accepted.
  def test_rejects_the_auth_parameter_when_auth_is_disabled
    start_server(auth: :disabled)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> AUTH=user@example.com\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_unknown_mail_from_parameter
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> FOO=bar\r\n")

    assert_match(/\A555 /, read_smtp_response(socket).to_s)
  end

  # A refused MAIL FROM leaves none of itself behind: AUTH= is read before the unknown
  # parameter refuses the command, and the next must not be audited under it.
  def test_does_not_leave_a_refused_auth_identity_on_the_envelope
    server = AuthIdentityServer.new(**server_options(auth: :required))
    start(server)

    socket = authenticated_connection(port)
    socket.print("MAIL FROM:<a@example.com> AUTH=ghost@example.com FOO=bar\r\n")
    assert_match(/\A555 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_nil server.seen_auth_identity
  end

  # The 552 lands after SIZE= has been read, and the message the client goes on
  # to send never declared one.
  def test_does_not_leave_a_refused_declared_size_on_the_envelope
    server = DeclaredSizeServer.new(**server_options(max_message_size: 100))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> SIZE=200\r\n")
    assert_match(/\A552 /, read_smtp_response(socket).to_s)
    deliver_message(socket)

    assert_nil server.seen_declared_size
  end

  # Every parameter the command got through before the unknown one refused it,
  # not just the last: SIZE= and BODY= are both accepted before FOO= is reached.
  def test_does_not_leave_the_parameters_read_before_a_refusal_on_the_envelope
    server = DeclaredSizeServer.new(**server_options(
      max_message_size: 10_000, eight_bit_mime: true
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> SIZE=500 BODY=8BITMIME FOO=bar\r\n")
    assert_match(/\A555 /, read_smtp_response(socket).to_s)
    deliver_message(socket)

    assert_nil server.seen_declared_size
    assert_nil server.last_body_encoding
  end

  # The application refuses after the engine has committed the parameters, so only
  # unwinding the session clears them — the hook has to see them while it decides.
  def test_does_not_leave_the_parameters_of_a_sender_the_application_refused
    server = RefusingSenderServer.new(**server_options(max_message_size: 10_000))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<#{RefusingSenderServer::REFUSED_SENDER}> SIZE=500\r\n")
    assert_match(/\A550 /, read_smtp_response(socket).to_s)
    assert_equal 500, server.seen_declared_size

    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_nil server.seen_declared_size
  end

  # RCPT TO advertises no ESMTP parameters at all, so even a real one from
  # another server's dictionary (DSN's NOTIFY=) is unimplemented here.
  def test_rejects_an_esmtp_parameter_on_rcpt_to
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com> NOTIFY=NEVER\r\n")

    assert_match(/\A555 /, read_smtp_response(socket).to_s)
  end

  # RFC 5321 §2.4: ESMTP keywords are case-insensitive, and a client sending
  # them lowercase must not have its parameters read as unknown ones.
  def test_reads_esmtp_parameter_keywords_in_any_case
    server = DeclaredSizeServer.new(**server_options(
      max_message_size: 10_000, eight_bit_mime: true, smtputf8: true
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com> size=512 body=7bit smtputf8\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nbody\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal 512, server.seen_declared_size
    assert_equal :seven_bit, server.last_body_encoding
    assert_equal true, server.last_smtputf8
  end

  # Where the parameter list starts is what the two path modes disagree about: strict has
  # no path to end, so an "=" in the tail names a parameter; optional makes it an address.
  def test_reads_an_unbracketed_path_carrying_an_equals_sign_as_the_address
    strict_listener = bind_listener
    lenient_port = port
    strict_port = port_of(strict_listener)
    server = ReceivingServer.new(**server_options(strict_path: false))
    start(server)
    start_server(listeners: [ strict_listener ])

    socket = connect(lenient_port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:a=b@example.com\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    strict_socket = connect(strict_port)
    read_smtp_response(strict_socket)
    strict_socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(strict_socket)
    strict_socket.print("MAIL FROM:a=b@example.com\r\n")
    assert_match(/\A555 /, read_smtp_response(strict_socket).to_s)

    assert_equal [ "a=b@example.com" ], server.mail_from_calls
  end

  private
    # AUTH= needs the AUTH extension on, and the engine's only "on" mode also requires
    # authentication before MAIL FROM — so get an AuthedServer session past both.
    def authenticated_connection(port)
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("EHLO test.client.example\r\n")
      read_smtp_lines(socket)
      socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0secret")}\r\n")
      read_smtp_response(socket)
      socket
    end

    # A whole transaction that declares nothing, on a session that already greeted — so
    # whatever the envelope carries into +receive+ was left there by an earlier command.
    def deliver_message(socket)
      socket.print("MAIL FROM:<a@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("RCPT TO:<b@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("DATA\r\n")
      assert_match(/\A354 /, read_smtp_response(socket).to_s)
      socket.print("Subject: hi\r\n\r\nbody\r\n.\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
    end
end
