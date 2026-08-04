require_relative "test_helper"

class MailSmtp::ParameterParserTest < MailSmtp::TestCase
  def test_reads_nothing_from_an_empty_tail
    assert_empty parser.mail_from_extensions_in("")
  end

  def test_reads_a_declared_size_in_base_ten
    # Integer("0100") would otherwise read as octal and under-report the size.
    assert_equal 100, parser.mail_from_extensions_in(" SIZE=0100")[:declared_size]
  end

  def test_refuses_a_declared_size_over_the_limit_with_552
    error = assert_raises(MailSmtp::MessageTooLarge) { parser.mail_from_extensions_in(" SIZE=2000") }

    assert_equal "552 5.3.4 Requested mail action aborted: exceeded storage allocation", error.response
  end

  def test_takes_the_first_declaration_when_a_parameter_is_repeated
    assert_equal 10, parser.mail_from_extensions_in(" SIZE=10 SIZE=20")[:declared_size]
    assert_equal :seven_bit, parser.mail_from_extensions_in(" BODY=7BIT BODY=8BITMIME")[:body_encoding]
  end

  def test_reads_the_body_type_only_when_8bitmime_is_on
    assert_equal :eight_bit_mime, parser.mail_from_extensions_in(" BODY=8bitmime")[:body_encoding]
    assert_equal :seven_bit, parser.mail_from_extensions_in(" BODY=7bit")[:body_encoding]
    assert_raises(MailSmtp::InvalidParameters) { minimal.mail_from_extensions_in(" BODY=8BITMIME") }
  end

  def test_refuses_a_body_type_it_does_not_know
    assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" BODY=BINARYMIME") }
  end

  def test_reads_smtputf8_only_when_it_is_on
    assert_equal true, parser.mail_from_extensions_in(" SMTPUTF8")[:smtputf8]
    assert_raises(MailSmtp::InvalidParameters) { minimal.mail_from_extensions_in(" SMTPUTF8") }
  end

  def test_refuses_a_non_ascii_tail_unless_smtputf8_is_on
    assert_raises(MailSmtp::InvalidParameters) { minimal.mail_from_extensions_in(" BODY=7bit ünknown") }
  end

  def test_keeps_the_null_auth_identity_as_an_empty_string
    # "<>" is the client asserting no identity, and must never look like a mailbox.
    assert_equal "", parser.mail_from_extensions_in(" AUTH=<>")[:auth_identity]
  end

  def test_leaves_the_auth_identity_nil_when_none_is_asserted
    assert_nil parser.mail_from_extensions_in(" SIZE=10")[:auth_identity]
  end

  def test_decodes_the_xtext_escapes_in_an_auth_identity
    assert_equal "user@example.com", parser.mail_from_extensions_in(" AUTH=user+40example.com")[:auth_identity]
  end

  def test_refuses_an_auth_identity_that_is_not_xtext
    # "+" and "=" are the two printable characters xtext reserves; an empty value is none.
    assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" AUTH=user+ZZexample.com") }
    assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" AUTH=user=example.com") }
    assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" AUTH=") }
  end

  def test_takes_an_unescaped_at_sign_in_an_auth_identity_as_xtext
    assert_equal "user@example.com", parser.mail_from_extensions_in(" AUTH=user@example.com")[:auth_identity]
  end

  def test_refuses_an_auth_identity_decoding_to_a_control_character
    # "+0A" would forge a line in whatever logs the claim.
    assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" AUTH=user+0Aadmin") }
  end

  def test_refuses_an_auth_identity_when_auth_is_disabled
    assert_raises(MailSmtp::InvalidParameters) { minimal.mail_from_extensions_in(" AUTH=<>") }
  end

  def test_refuses_a_parameter_it_does_not_implement_with_555
    error = assert_raises(MailSmtp::ParametersNotRecognized) { parser.mail_from_extensions_in(" RET=FULL") }

    assert_equal "555 5.5.4 MAIL FROM/RCPT TO parameters not recognized or not implemented", error.response
    assert_raises(MailSmtp::ParametersNotRecognized) { parser.mail_from_extensions_in(" SIZE=10 RET=FULL") }
  end

  def test_refuses_a_leftover_that_is_no_parameter_at_all_with_501
    error = assert_raises(MailSmtp::InvalidParameters) { parser.mail_from_extensions_in(" <second@example.com>") }

    assert_equal "501 5.5.4 Syntax error in parameters or arguments", error.response
  end

  def test_accepts_every_extension_at_once
    extensions = parser.mail_from_extensions_in(" SIZE=100 BODY=8BITMIME SMTPUTF8 AUTH=user+40example.com")

    assert_equal({ declared_size: 100, body_encoding: :eight_bit_mime, smtputf8: true,
      auth_identity: "user@example.com" }, extensions)
  end

  def test_accepts_no_parameters_at_all_for_a_command_that_advertises_none
    assert_nil parser.raise_if_unhandled("")
    assert_nil parser.raise_if_unhandled("   ")
  end

  def test_refuses_an_unhandled_parameter_by_whether_it_still_parses_as_one
    assert_raises(MailSmtp::ParametersNotRecognized) { parser.raise_if_unhandled(" NOTIFY=NEVER") }
    assert_raises(MailSmtp::InvalidParameters) { parser.raise_if_unhandled(" junk") }
  end

  private
    def parser
      @parser ||= MailSmtp::ParameterParser.new(max_message_size: 1000,
        eight_bit_mime: true, smtputf8: true, auth_enabled: true)
    end

    # Every extension off: SIZE alone is always read, the rest earn a refusal.
    def minimal
      @minimal ||= MailSmtp::ParameterParser.new(max_message_size: nil,
        eight_bit_mime: false, smtputf8: false, auth_enabled: false)
    end
end
