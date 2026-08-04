require_relative "test_helper"

class MailSmtp::AuthTest < MailSmtp::ServerIntegrationTest
  def test_does_not_advertise_auth_before_tls_when_starttls_required
    tls = Object.new
    def tls.start(io) = io
    start_server(auth: :required, starttls: :required, tls: tls)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)

    refute lines.any? { |line| line.include?("AUTH") }
    assert lines.any? { |line| line.include?("STARTTLS") }
  end

  def test_requires_authentication_before_mail_from_when_auth_is_required
    start_server(auth: :required)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A530 /, read_smtp_response(socket).to_s)
  end

  def test_authenticates_with_plain_and_accepts_mail
    server = AuthedServer.new(**server_options(auth: :required))
    start(server)

    with_smtp(port) do |smtp|
      smtp.authenticate("user", "secret", :plain)
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\n\r\nHi\r\n",
        "a@example.com", "b@example.com")
    end

    assert_equal "user", server.authenticated_as
    assert_equal "a@example.com", server.received[:from]
  end

  def test_starttls_discards_authentication_asserted_in_the_clear
    server = AuthedServer.new(**server_options(
      auth: :required,
      starttls: :optional,
      tls: FakeTls.new
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0secret")}\r\n")
    assert_match(/\A235 /, read_smtp_response(socket).to_s)

    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    # The greeting is gone too, so EHLO first — otherwise MAIL FROM answers 503
    # for being out of sequence and says nothing about the credential.
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A530 /, read_smtp_response(socket).to_s)

    # Proving it again inside the session is all it takes.
    socket.print("AUTH PLAIN #{Base64.strict_encode64("\0user\0secret")}\r\n")
    assert_match(/\A235 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_closes_after_max_auth_failures
    start(AuthedServer.new(**server_options(auth: :required, max_auth_failures: 2, max_exceptions: nil)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    bad = Base64.strict_encode64("\0user\0wrong")
    socket.print("AUTH PLAIN #{bad}\r\n")
    assert_match(/\A535 /, read_smtp_response(socket).to_s)
    socket.print("AUTH PLAIN #{bad}\r\n")
    assert_match(/\A535 /, read_smtp_response(socket).to_s)

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # split("\x00") alone drops the trailing empty field, so "\0user\0" would parse as
  # 2 fields and 501 instead of failing authentication.
  def test_auth_plain_with_empty_password_counts_as_a_failed_attempt
    start(AuthedServer.new(**server_options(auth: :required, max_auth_failures: 1, max_exceptions: nil)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    empty_password = Base64.strict_encode64("\0user\0")
    socket.print("AUTH PLAIN #{empty_password}\r\n")
    assert_match(/\A535 /, read_smtp_response(socket).to_s)

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_accepts_auth_plain_longer_than_command_line_limit
    start(AuthedServer.new(**server_options(auth: :required)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    # Pad so the AUTH line exceeds the 512-octet command ceiling; still a 535.
    encoded = Base64.strict_encode64("\0user\0#{"y" * 600}")
    refute_operator encoded.bytesize + "AUTH PLAIN ".bytesize + 2, :<, MailSmtp::Server::MAX_COMMAND_LINE_LENGTH
    socket.print("AUTH PLAIN #{encoded}\r\n")

    assert_match(/\A535 /, read_smtp_response(socket).to_s)
  end

  def test_accepts_auth_plain_continuation_of_800_octets
    start(AuthedServer.new(**server_options(auth: :required, max_auth_failures: nil)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH PLAIN\r\n")
    assert_match(/\A334 /, read_smtp_response(socket).to_s)

    # RFC 4954 §4: continuations may be far above the 512-octet command limit.
    encoded = Base64.strict_encode64("\0user\0#{"y" * 600}")
    assert_operator encoded.bytesize, :>=, 800
    assert_operator encoded.bytesize + 2, :<, MailSmtp::Server::MAX_AUTH_LINE_LENGTH
    socket.print("#{encoded}\r\n")

    assert_match(/\A535 /, read_smtp_response(socket).to_s)
  end

  def test_authenticates_with_login
    server = AuthedServer.new(**server_options(auth: :required))
    start(server)

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

    assert_equal "user", server.authenticated_as
  end

  def test_auth_mechanisms_controls_ehlo_advertisement_and_acceptance
    start(PlainOnlyAuthServer.new(**server_options(auth: :required)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    lines = read_smtp_lines(socket)

    auth_line = lines.find { |line| line.include?("AUTH") }
    assert_equal "250-AUTH PLAIN", auth_line
    refute_match(/LOGIN/, auth_line)

    socket.print("AUTH LOGIN\r\n")
    assert_match(/\A504 /, read_smtp_response(socket).to_s)

    encoded = Base64.strict_encode64("\0user\0secret")
    socket.print("AUTH PLAIN #{encoded}\r\n")
    assert_match(/\A235 /, read_smtp_response(socket).to_s)
  end

  def test_auth_login_with_initial_response_then_password
    server = AuthedServer.new(**server_options(auth: :required))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH LOGIN #{Base64.strict_encode64("user")}\r\n")
    assert_match(/\A334 /, read_smtp_response(socket).to_s)
    socket.print("#{Base64.strict_encode64("secret")}\r\n")
    assert_match(/\A235 /, read_smtp_response(socket).to_s)
    assert_equal "user", server.authenticated_as
  end

  def test_auth_login_rejects_bad_password
    start(AuthedServer.new(**server_options(auth: :required, max_auth_failures: nil)))

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH LOGIN\r\n")
    read_smtp_response(socket)
    socket.print("#{Base64.strict_encode64("user")}\r\n")
    read_smtp_response(socket)
    socket.print("#{Base64.strict_encode64("nope")}\r\n")

    assert_match(/\A535 /, read_smtp_response(socket).to_s)
  end

  def test_starttls_wipes_pre_tls_authentication
    server = AuthedServer.new(**server_options(
      auth: :required,
      tls: FakeTls.new,
      starttls: :optional
    ))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    encoded = Base64.strict_encode64("\0user\0secret")
    socket.print("AUTH PLAIN #{encoded}\r\n")
    assert_match(/\A235 /, read_smtp_response(socket).to_s)

    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")

    assert_match(/\A530 /, read_smtp_response(socket).to_s)
  end

  def test_loggable_command_redacts_auth_credentials
    server = MailSmtp::Server.new(**server_options)
    session = MailSmtp::Session.new

    session.phase = :ready
    assert_equal "EHLO client.example", server.send(:loggable_command, session, "EHLO client.example")
    assert_equal "AUTH LOGIN", server.send(:loggable_command, session, "AUTH LOGIN")
    assert_equal "AUTH PLAIN [redacted]",
      server.send(:loggable_command, session, "AUTH PLAIN AHVzZXIAcGFzcw==")
    assert_equal "AUTH LOGIN [redacted]",
      server.send(:loggable_command, session, "AUTH LOGIN dXNlcg==")

    %i[ auth_plain auth_login_user auth_login_pass ].each do |phase|
      session.phase = phase
      assert_equal "[redacted credential]",
        server.send(:loggable_command, session, "AHVzZXIAcGFzcw=="),
        "phase #{phase}"
    end
  end

  def test_does_not_log_a_pipelined_auth_credential_verbatim
    log_io = StringIO.new
    logger = Logger.new(log_io)
    logger.level = Logger::DEBUG
    start(AuthedServer.new(**server_options(auth: :required, logger: logger)))

    credential = Base64.strict_encode64("\0user\0secret")

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    # Command and credential in one segment: the pipelined continuation must be
    # dropped, not read back and logged.
    socket.print("AUTH PLAIN\r\n#{credential}\r\n")
    assert_match(/\A500 /, read_smtp_response(socket).to_s)

    socket.print("QUIT\r\n")
    read_smtp_response(socket)
    wait_until_idle(@servers.last)

    logged = log_io.string
    assert_match(/PipeliningNotSupported/, logged)
    refute_includes logged, credential
    refute_includes logged, "secret"
  end

  def test_authenticates_auth_plain_with_plus_and_slash_in_base64
    # Bytes that encode to "++++" / "////" so the initial response exercises
    # base64's non-alphanumeric alphabet (ported from PostRider submission tests).
    username = "us".b + [ 0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF ].pack("C*")
    server = Class.new(ReceivingServer) do
      define_method(:authenticate) do |_session, username:, password:, authorization_id: ""|
        raise MailSmtp::AuthenticationFailed unless password == "secret"
        username
      end
    end.new(**server_options(auth: :required))
    start(server)

    credential = Base64.strict_encode64("\0".b + username + "\0secret")
    assert_includes credential, "+"
    assert_includes credential, "/"

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH PLAIN #{credential}\r\n")

    assert_match(/\A235 /, read_smtp_response(socket).to_s)
  end

  # SASL PLAIN's authzid is a client claim; it must never become the identity on its own.
  def test_auth_plain_authzid_is_refused_when_the_application_does_not_grant_it
    # The idiomatic hook: validate, raise on failure, no explicit return value.
    server = authzid_server { |_authzid| nil }
    start(server)

    assert_match(/\A535 /, authenticate_with_authzid(port, "victim"))
    assert_nil server.granted_authorization_id
  end

  def test_auth_plain_without_an_authzid_authorizes_the_authenticated_account
    server = authzid_server { |_authzid| nil }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "", envelope: true))
    assert_equal "user", server.granted_authorization_id
  end

  def test_auth_plain_authzid_matching_the_account_is_accepted
    server = authzid_server { |_authzid| nil }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "user", envelope: true))
    assert_equal "user", server.granted_authorization_id
  end

  def test_application_grants_an_authzid_by_returning_it
    server = authzid_server { |authzid| authzid }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "victim", envelope: true))
    assert_equal "victim", server.granted_authorization_id
    assert_equal "victim", server.requested_authorization_id
  end

  # +true+ from a hook means "authenticated", not "and the identity is true".
  def test_a_non_string_return_does_not_become_the_authorization_identity
    server = authzid_server { |_authzid| true }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "", envelope: true))
    assert_equal "user", server.granted_authorization_id
  end

  # RFC 4616 §2 allows an authzid equal to the authcid; a canonicalizing answer
  # must not be compared byte-for-byte against it.
  def test_accepts_authzid_equal_to_the_account_when_the_application_canonicalizes
    server = authzid_server { |_authzid| "canonical@example.com" }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "user", envelope: true))
    assert_equal "canonical@example.com", server.granted_authorization_id
  end

  # An explicit grant is authoritative; the client's differing claim is simply ignored.
  def test_an_explicit_grant_overrides_a_differing_client_claim
    server = authzid_server { |_authzid| "canonical@example.com" }
    start(server)

    assert_match(/\A235 /, authenticate_with_authzid(port, "victim", envelope: true))
    assert_equal "canonical@example.com", server.granted_authorization_id
    assert_equal "victim", server.requested_authorization_id
  end

  # base64 can carry CR/LF, which would forge header lines once logged.
  def test_rejects_a_sasl_identity_containing_crlf
    server = authzid_server { |_authzid| nil }
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("AUTH PLAIN #{Base64.strict_encode64("\0vic\r\nInjected: yes\0secret")}\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  # An application-assembled identity is held to the same CR/LF rule as one off the wire.
  def test_refuses_an_application_granted_identity_containing_crlf
    server = authzid_server { |_authzid| "vic\r\nInjected: yes" }
    start(server)

    assert_match(/\A451 /, authenticate_with_authzid(port, ""))
  end

  private
    def authzid_server(&block)
      Class.new(ReceivingServer) do
        attr_reader :granted_authorization_id, :requested_authorization_id

        define_method(:authenticate) do |_session, username:, password:, authorization_id: ""|
          raise MailSmtp::AuthenticationFailed unless username == "user" && password == "secret"
          block.call(authorization_id)
        end

        define_method(:mail_from) do |session, address|
          @granted_authorization_id = session.authorization_id
          @requested_authorization_id = session.requested_authorization_id
          address
        end
      end.new(**server_options(auth: :required))
    end

    def authenticate_with_authzid(port, authzid, envelope: false)
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("EHLO test.client.example\r\n")
      read_smtp_lines(socket)
      socket.print("AUTH PLAIN #{Base64.strict_encode64("#{authzid}\0user\0secret")}\r\n")
      response = read_smtp_response(socket).to_s

      if envelope
        socket.print("MAIL FROM:<a@example.com>\r\n")
        read_smtp_response(socket)
      end

      response
    end
end
