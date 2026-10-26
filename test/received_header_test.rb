require_relative "test_helper"

class MailSmtp::ReceivedHeaderTest < MailSmtp::ServerIntegrationTest
  def test_prepends_received_header_when_enabled
    server = ReceivingServer.new(**server_options(add_received: true))
    start(server)

    with_smtp(port) do |smtp|
      smtp.send_message("From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nBody.\r\n",
        "a@example.com", "b@example.com")
    end

    assert_match(/\AReceived: from /, server.received[:data])
  end

  def test_ordinary_helo_names_reach_the_received_header_untouched
    server = ReceivingServer.new(**server_options(add_received: true))
    start(server)

    deliver_with_helo(port, "mail-01.test.client.example")

    assert_equal "mail-01.test.client.example",
      server.received[:data].to_s[/\AReceived: from (\S+) /, 1]
  end

  def test_whitespace_around_a_helo_name_is_dropped
    server = ReceivingServer.new(**server_options(add_received: true))
    start(server)

    deliver_with_helo(port, " \t mail-01.test.client.example \t")

    assert_equal "mail-01.test.client.example",
      server.received[:data].to_s[/\AReceived: from (\S+) /, 1]
  end

  # CR/LF are already stripped; this guards against forgery via an unbalanced "(" hiding the real client IP.
  def test_neuters_a_hostile_helo_before_it_reaches_the_received_header
    server = ReceivingServer.new(**server_options(add_received: true))
    start(server)

    deliver_with_helo(port, "evil\x00.com\x07 (forged [10.0.0.1])")

    header = server.received[:data].to_s.lines.first.to_s
    # NUL, BEL, the space and both parens each become one "?", 1:1.
    assert_equal "evil?.com???forged?[10.0.0.1]?", header[/\AReceived: from (\S+) /, 1]
    assert_equal "(unknown [127.0.0.1])", header[/ (\(unknown \[[^\]]+\]\)) /, 1]
    refute_match(/[^\x20-\x7e]/, header.chomp)
  end

  # An internationalized domain is legitimate once SMTPUTF8 is negotiated.
  def test_keeps_a_well_formed_utf8_helo_for_an_smtputf8_message
    server = ReceivingServer.new(**server_options(add_received: true, smtputf8: true, eight_bit_mime: true))
    start(server)

    deliver_with_helo(port, "münchen.example", smtputf8: true)

    header = server.received[:data].to_s.dup.force_encoding(Encoding::UTF_8)
    assert_equal "münchen.example", header[/\AReceived: from (\S+) /, 1]
  end

  # RFC 5322 §2.2 header bodies are US-ASCII unless this message used SMTPUTF8
  # (RFC 6532), known only once the envelope is in hand.
  def test_downgrades_a_utf8_helo_for_a_message_that_did_not_use_smtputf8
    server = ReceivingServer.new(**server_options(add_received: true, smtputf8: true, eight_bit_mime: true))
    start(server)

    deliver_with_helo(port, "münchen.example", smtputf8: false)

    header = server.received[:data].to_s.lines.first.to_s
    # Byte-for-byte, the same as a server without smtputf8 would have written.
    assert_equal "m??nchen.example", header[/\AReceived: from (\S+) /, 1]
    refute_match(/[^\x20-\x7e]/, header.chomp)
  end

  def test_still_neuters_specials_and_format_characters_under_smtputf8
    server = ReceivingServer.new(**server_options(add_received: true, smtputf8: true, eight_bit_mime: true))
    start(server)

    # U+200D (zero-width joiner) lets a name render as something other than its bytes.
    deliver_with_helo(port, "m\u00FCn\u200Dchen(evil", smtputf8: true)

    header = server.received[:data].to_s.dup.force_encoding(Encoding::UTF_8)
    assert_equal "mün?chen?evil", header[/\AReceived: from (\S+) /, 1]
  end

  def test_neuters_non_ascii_helo_when_smtputf8_is_disabled
    server = ReceivingServer.new(**server_options(add_received: true))
    start(server)

    deliver_with_helo(port, "münchen.example")

    # "ü" is two UTF-8 bytes, and each one is replaced.
    assert_equal "m??nchen.example", server.received[:data].to_s[/\AReceived: from (\S+) /, 1]
  end

  def test_falls_back_to_ascii_only_when_an_smtputf8_helo_is_malformed
    server = ReceivingServer.new(**server_options(add_received: true, smtputf8: true, eight_bit_mime: true))
    start(server)

    # A lead byte with no continuation — never reaches a header half-decoded.
    deliver_with_helo(port, "bad\xC3(".b)

    assert_equal "bad??", server.received[:data].to_s[/\AReceived: from (\S+) /, 1]
  end

  def test_neuters_unicode_separators_and_spaces_under_smtputf8
    server = ReceivingServer.new(**server_options(add_received: true, smtputf8: true, eight_bit_mime: true))
    start(server)

    # NBSP/U+3000 would undo the ASCII-space rule; U+2028 ends a line the same way CR/LF would.
    deliver_with_helo(port, "a\u00A0b\u2028c\u3000d")

    header = server.received[:data].to_s.dup.force_encoding(Encoding::UTF_8)
    assert_equal "a?b?c?d", header[/\AReceived: from (\S+) /, 1]
  end

  # session.helo is public, so an application can set it directly, bypassing the
  # neuter_helo the engine's own EHLO path applies — ascii_only_helo is the backstop
  # re-check for exactly that, and must not let CR/LF forge a header line.
  def test_ascii_only_helo_strips_crlf_from_an_application_set_helo_under_smtputf8
    server = MailSmtp::Server.new(**server_options(smtputf8: true, eight_bit_mime: true))
    session = MailSmtp::Session.new
    session.envelope.smtputf8 = true

    result = server.send(:ascii_only_helo, session, "evil\r\nX-Injected: header")

    refute_match(/[\r\n]/, result)
  end

  private
    def deliver_with_helo(port, helo, smtputf8: false)
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("EHLO ".b << helo.b << "\r\n".b)
      read_smtp_lines(socket)
      socket.print("MAIL FROM:<a@example.com>#{" SMTPUTF8" if smtputf8}\r\n")
      read_smtp_response(socket)
      socket.print("RCPT TO:<b@example.com>\r\n")
      read_smtp_response(socket)
      socket.print("DATA\r\n")
      read_smtp_response(socket)
      socket.print("Body.\r\n.\r\n")
      read_smtp_response(socket)
      # The 250 above already means +receive+ returned. Hang up before waiting, or
      # wait_until_idle sits on our own still-open connection until its timeout.
      close(socket)
      wait_until_idle(@servers.last)
    end
end
