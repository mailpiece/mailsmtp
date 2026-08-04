require_relative "test_helper"

class MailSmtp::EnvelopeTest < MailSmtp::ServerIntegrationTest
  def test_rejects_recipients_past_the_configured_ceiling
    start_server(max_recipients: 100)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    100.times do |i|
      socket.print("RCPT TO:<u#{i}@example.com>\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
    end

    socket.print("RCPT TO:<one-more@example.com>\r\n")
    assert_match(/\A452 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_nul_in_mail_from
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a\0b@example.com>\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_hands_the_subclass_the_mailbox_inside_the_brackets
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: "<a@example.com>", to: "<b@example.com>")

    assert_equal "a@example.com", server.received[:from]
    assert_equal [ "b@example.com" ], server.received[:to]
    assert_equal [ "a@example.com" ], server.mail_from_calls
  end

  # An unbracketed path leaves the address/parameter boundary to guesswork, and the
  # senders that break under a strict parser break on their local part, not brackets.
  def test_requires_angle_brackets_on_the_path
    server = ReceivingServer.new(**server_options)
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:a@example.com\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:b@example.com\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    assert_equal [ "a@example.com" ], server.mail_from_calls
  end

  # Port 25 hears from appliances that never learned the brackets, and a permanent 501
  # bounces their mail. With +strict_path: false+ the address runs to the first space.
  def test_accepts_an_unbracketed_path_when_the_brackets_are_optional
    server = ReceivingServer.new(**server_options(strict_path: false))
    start(server)

    deliver_envelope(port, from: "user@example.com", to: "b@example.com")
    deliver_envelope(port, from: " spaced@example.com", to: "  c@example.com")

    assert_equal [ "user@example.com", "spaced@example.com" ], server.mail_from_calls
    assert_equal "spaced@example.com", server.received[:from]
    assert_equal [ "c@example.com" ], server.received[:to]
  end

  # The space that ends the address is where the parameter list begins, so both
  # halves of the command still have to be read.
  def test_reads_the_esmtp_parameters_after_an_unbracketed_path
    server = DeclaredSizeServer.new(**server_options(strict_path: false, max_message_size: 1000))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:user@example.com SIZE=100\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:b@example.com\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nBody.\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal 100, server.seen_declared_size
    assert_equal "user@example.com", server.received[:from]
    assert_equal [ "b@example.com" ], server.received[:to]
  end

  # Optional brackets are not half brackets: one of them, or one inside the
  # address, is a path nobody can frame rather than a boundary to guess at.
  def test_rejects_a_half_bracketed_path_when_the_brackets_are_optional
    server = ReceivingServer.new(**server_options(strict_path: false))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    [
      "<a@example.com",
      "a@example.com>",
      "a<b@example.com",
      "<a<b@example.com>",
      "><",
      "<a@example.com> <b@example.com>",
      "<a@example.com> junk"
    ].each do |path|
      socket.print("MAIL FROM:#{path}\r\n")
      assert_match(/\A501 /, read_smtp_response(socket).to_s, "expected 501 for MAIL FROM:#{path}")
    end

    assert_equal [], server.mail_from_calls
  end

  # The null sender is the literal "<>" whether or not the brackets are required, so
  # an empty tail is a syntax error — otherwise dropping them would forge one.
  def test_refuses_an_empty_unbracketed_path_rather_than_reading_it_as_the_null_sender
    server = ReceivingServer.new(**server_options(strict_path: false))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    [ "", " ", "\t", "@relay.example:", "@a.example,@b.example:" ].each do |path|
      socket.print("MAIL FROM:#{path}\r\n")
      assert_match(/\A501 /, read_smtp_response(socket).to_s, "expected 501 for MAIL FROM:#{path}")
    end

    socket.print("MAIL FROM:<>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO: \r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)

    assert_equal [ "" ], server.mail_from_calls
  end

  # Everything the brackets used to hold is still held to: source route, quoted local
  # part, length ceiling and ASCII rule refuse a bare path exactly as a bracketed one.
  def test_applies_the_mailbox_rules_to_an_unbracketed_path
    server = ReceivingServer.new(**server_options(strict_path: false))
    start(server)

    over_limit = "#{"a" * (257 - "@example.com".length)}@example.com"

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    [ '"a b"@example.com', '"ab"@example.com', "usér@example.com", over_limit ].each do |path|
      socket.print("MAIL FROM:#{path}\r\n")
      assert_match(/\A501 /, read_smtp_response(socket).to_s, "expected 501 for MAIL FROM:#{path}")
    end

    socket.print("MAIL FROM:@relay1.example,@relay2.example:a@example.com\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:@relay3.example:b@example.com\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nBody.\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal [ "a@example.com" ], server.mail_from_calls
    assert_equal [ "b@example.com" ], server.received[:to]
  end

  # The space costs nothing to allow: the brackets still say exactly where the
  # address begins and ends.
  def test_tolerates_whitespace_between_the_colon_and_the_path
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: " <a@example.com>", to: "  <b@example.com>")

    assert_equal "a@example.com", server.received[:from]
    assert_equal [ "b@example.com" ], server.received[:to]
  end

  # Legal RFC 5321, refused on purpose: accepting it would mean everything downstream
  # needs a quoted-string scanner to agree with the engine where the local part ends.
  def test_rejects_a_quoted_local_part
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    [
      '<"a b"@example.com>',
      '<"a>b"@example.com>',
      '<"a@b"@example.com>',
      '<@relay.example:"a b"@example.com>'
    ].each do |path|
      socket.print("MAIL FROM:#{path}\r\n")
      assert_match(/\A501 /, read_smtp_response(socket).to_s, "expected 501 for MAIL FROM:#{path}")
    end
  end

  # A parameter is only ever what follows the closing ">". Scanning the whole command
  # tail read this address's middle as SIZE= and left the mailbox with a hole in it.
  def test_does_not_read_an_esmtp_parameter_out_of_the_address
    server = ReceivingServer.new(**server_options(max_message_size: 100))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print(%(MAIL FROM:<"pay SIZE=99999 me"@example.com>\r\n))

    # 501 for the quoted local part — never 552 for a size nobody sent.
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    assert_equal [], server.mail_from_calls
  end

  # The forward-path ends at its ">" for the same reason the reverse-path does: scanning
  # the whole tail answered 555 for " SIZE=1 " instead of 501 for a quoted local part.
  def test_does_not_read_an_esmtp_parameter_out_of_the_forward_path
    server = ReceivingServer.new(**server_options)
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print(%(RCPT TO:<"pay SIZE=1 me"@example.com>\r\n))
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    # An "=" the mailbox simply carries is not a parameter either — this is the
    # Gmail forwarding form real senders deliver to.
    socket.print("RCPT TO:<user+caf_=x@gmail.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nBody.\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    assert_equal [ "user+caf_=x@gmail.com" ], server.received[:to]
  end

  # What follows the forward-path is unimplemented if it parses as a parameter
  # and a syntax error if it doesn't — the same split the reverse-path makes.
  def test_rejects_trailing_junk_after_the_forward_path
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<b@example.com> junk\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_rejects_a_path_longer_than_256_octets
    server = ReceivingServer.new(**server_options)
    start(server)

    at_limit = "#{"a" * (254 - "@example.com".length)}@example.com"
    over_limit = "#{"a" * (255 - "@example.com".length)}@example.com"

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<#{at_limit}>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RSET\r\n")
    read_smtp_response(socket)
    socket.print("MAIL FROM:<#{over_limit}>\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("RCPT TO:<#{over_limit}>\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    assert_equal [ at_limit, "a@example.com" ], server.mail_from_calls
  end

  # An internationalized mailbox rides on SMTPUTF8 (RFC 6531 §3.4); without it
  # the engine owes the application ASCII envelope strings, on both paths.
  def test_rejects_a_non_ascii_path_without_smtputf8
    server = ReceivingServer.new(**server_options)
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<usér@example.com>\r\n")
    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<récipient@example.com>\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    assert_equal [ "a@example.com" ], server.mail_from_calls
  end

  def test_accepts_a_non_ascii_path_under_smtputf8
    server = ReceivingServer.new(**server_options(smtputf8: true, eight_bit_mime: true))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<usér@example.com> SMTPUTF8\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("RCPT TO:<récipient@example.com>\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("DATA\r\n")
    assert_match(/\A354 /, read_smtp_response(socket).to_s)
    socket.print("Subject: hi\r\n\r\nBody.\r\n.\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)

    # The envelope arrives as UTF-8, so nothing downstream has to re-tag the bytes
    # before it can compare, store, or serialize the address.
    assert_equal "usér@example.com", server.received[:from]
    assert_equal [ "récipient@example.com" ], server.received[:to]
    assert_equal Encoding::UTF_8, server.received[:from].encoding
  end

  def test_refuses_a_path_that_is_not_valid_utf8_under_smtputf8
    server = ReceivingServer.new(**server_options(smtputf8: true, eight_bit_mime: true))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<b\xC3(d@example.com> SMTPUTF8\r\n".b)

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
    assert_empty server.mail_from_calls
  end

  def test_hands_over_a_utf8_envelope_even_when_smtputf8_is_off
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: "<a@example.com>", to: "<b@example.com>")

    assert_equal Encoding::UTF_8, server.received[:from].encoding
    assert_equal Encoding::UTF_8, server.received[:to].first.encoding
  end

  # The 64-octet local-part limit (RFC 5321 §4.5.3.1.1) is deliberately not enforced: it
  # refuses mail people send — Gmail's forwarding form is 70 octets of local part.
  def test_accepts_a_local_part_longer_than_64_octets
    server = ReceivingServer.new(**server_options)
    start(server)

    forwarded = "someone+caf_=#{"recipient" * 5}=example.com@gmail.com"
    assert_operator forwarded.split("@").first.length, :>, 64

    deliver_envelope(port, from: "<a@example.com>", to: "<#{forwarded}>")

    assert_equal [ forwarded ], server.received[:to]
  end

  def test_strips_a_source_route_from_both_paths
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: "<@relay1.example,@relay2.example:a@example.com>",
      to: "<@relay3.example:b@example.com>")

    assert_equal "a@example.com", server.received[:from]
    assert_equal [ "b@example.com" ], server.received[:to]
  end

  def test_rejects_malformed_path_framing
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)

    [
      "<a@example.com",             # unclosed
      "a@example.com>",             # unopened
      "<a@example.com> <b@example.com>", # two paths
      "a@example.com b@example.com",     # two paths, unbracketed
      "<a@example.com> junk",       # trailing junk
      "<a<b@example.com>",          # bracket inside the path
      # None of these are the null sender: only a literally empty "<>" is.
      "",
      "   ",
      "< >",
      "<@relay1.example:>",
      "<@a.example,@b.example:>"
    ].each do |path|
      socket.print("MAIL FROM:#{path}\r\n")
      assert_match(/\A501 /, read_smtp_response(socket).to_s, "expected 501 for MAIL FROM:#{path}")
    end
  end

  def test_accepts_the_null_reverse_path
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: "<>", to: "<b@example.com>")

    assert_equal "", server.received[:from]
    assert_equal [ "" ], server.mail_from_calls
  end

  def test_rejects_an_empty_forward_path
    start_server

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("MAIL FROM:<a@example.com>\r\n")
    read_smtp_response(socket)
    socket.print("RCPT TO:<>\r\n")

    assert_match(/\A501 /, read_smtp_response(socket).to_s)
  end

  def test_accepts_a_bare_postmaster_forward_path
    server = ReceivingServer.new(**server_options)
    start(server)

    deliver_envelope(port, from: "<a@example.com>", to: "<Postmaster>")

    assert_equal [ "Postmaster" ], server.received[:to]
  end

  def test_null_sender_is_an_empty_reverse_path_and_not_an_unstarted_transaction
    envelope = MailSmtp::Session.new.envelope

    refute_predicate envelope, :null_sender?

    envelope.from = ""
    assert_predicate envelope, :null_sender?

    envelope.from = "a@example.com"
    refute_predicate envelope, :null_sender?
  end

  private
    # Runs one whole transaction with the paths written exactly as given, so a
    # test can assert what the framing left for the subclass.
    def deliver_envelope(port, from:, to:)
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("EHLO test.client.example\r\n")
      read_smtp_lines(socket)
      socket.print("MAIL FROM:#{from}\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("RCPT TO:#{to}\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)
      socket.print("DATA\r\n")
      assert_match(/\A354 /, read_smtp_response(socket).to_s)
      socket.print("Subject: hi\r\n\r\nBody.\r\n.\r\n")
      assert_match(/\A250 /, read_smtp_response(socket).to_s)

      close(socket)
      wait_until_idle(@servers.last)
    end
end
