require_relative "test_helper"

class MailSmtp::PathParserTest < MailSmtp::TestCase
  def test_splits_a_bracketed_path_from_the_parameters_behind_it
    assert_equal [ "<sender@example.com>", " SIZE=100" ],
      strict.split_from_parameters("<sender@example.com> SIZE=100")
  end

  def test_ends_the_path_at_its_closing_bracket_rather_than_scanning_the_whole_tail
    # A quoted local part naming SIZE= must not be read as a declared size.
    path, parameters = strict.split_from_parameters(%(<"pay SIZE=1 me"@example.com> SIZE=900))

    assert_equal %(<"pay SIZE=1 me"@example.com>), path
    assert_equal " SIZE=900", parameters
  end

  def test_leaves_the_whole_tail_as_parameters_when_no_closing_bracket_arrives
    assert_equal [ "<sender@example.com", "<sender@example.com" ],
      strict.split_from_parameters("<sender@example.com")
  end

  def test_splits_an_unbracketed_path_at_the_first_space_when_brackets_are_optional
    assert_equal [ "sender@example.com", " SIZE=100" ],
      loose.split_from_parameters("sender@example.com SIZE=100")
  end

  def test_reads_an_unbracketed_path_carrying_an_equals_sign_as_the_address
    assert_equal [ "a=b@example.com", "" ], loose.split_from_parameters("a=b@example.com")
    assert_equal "a=b@example.com", loose.address_in("a=b@example.com")
  end

  def test_keeps_an_unbracketed_path_whole_under_strict_brackets_so_it_earns_its_own_501
    assert_equal [ "sender@example.com SIZE=100", "sender@example.com SIZE=100" ],
      strict.split_from_parameters("sender@example.com SIZE=100")
  end

  def test_unwraps_a_bracketed_path_to_the_bare_mailbox
    assert_equal "sender@example.com", strict.address_in("<sender@example.com>")
  end

  def test_trims_the_space_inside_the_brackets
    assert_equal "sender@example.com", strict.address_in("< sender@example.com >")
  end

  def test_reads_the_null_sender_as_an_empty_string
    assert_equal "", strict.address_in("<>")
  end

  def test_refuses_anything_but_a_literally_empty_pair_of_brackets_as_the_null_sender
    error = assert_raises(MailSmtp::InvalidParameters) { strict.address_in("< >") }

    assert_equal "Malformed path", error.message
  end

  def test_ignores_a_source_route_and_keeps_the_mailbox_after_it
    assert_equal "user@example.com", strict.address_in("<@relay.example.net:user@example.com>")
  end

  def test_refuses_a_source_route_with_no_mailbox_behind_it
    # Stripping the route must not leave "" and forge the null sender.
    assert_raises(MailSmtp::InvalidParameters) { strict.address_in("<@relay.example.net:>") }
  end

  def test_refuses_a_quoted_local_part
    error = assert_raises(MailSmtp::InvalidParameters) { strict.address_in(%(<"a b"@example.com>)) }

    assert_equal "Quoted local part", error.message
  end

  def test_refuses_a_half_bracketed_path
    assert_raises(MailSmtp::InvalidParameters) { strict.address_in("<sender@example.com") }
    assert_raises(MailSmtp::InvalidParameters) { loose.address_in("sender@example.com>") }
  end

  def test_refuses_an_unbracketed_path_under_strict_brackets
    assert_raises(MailSmtp::InvalidParameters) { strict.address_in("sender@example.com") }
  end

  def test_refuses_an_empty_unbracketed_path_rather_than_reading_it_as_the_null_sender
    assert_raises(MailSmtp::InvalidParameters) { loose.address_in("") }
  end

  def test_applies_the_mailbox_rules_to_an_unbracketed_path
    assert_equal "user@example.com", loose.address_in("@relay.example.net:user@example.com")
    assert_raises(MailSmtp::InvalidParameters) { loose.address_in(%("a b"@example.com)) }
  end

  def test_accepts_a_path_of_exactly_the_256_octet_limit
    path = "<#{"a" * 242}@example.com>"

    assert_equal MailSmtp::PathParser::MAX_PATH_LENGTH, path.bytesize
    assert_equal "#{"a" * 242}@example.com", strict.address_in(path)
  end

  def test_refuses_a_path_one_octet_over_the_limit
    error = assert_raises(MailSmtp::InvalidParameters) { strict.address_in("<#{"a" * 243}@example.com>") }

    assert_equal "Path too long", error.message
  end

  def test_refuses_a_path_one_octet_over_the_limit_unbracketed
    assert_raises(MailSmtp::InvalidParameters) { loose.address_in("#{"a" * 245}@example.com") }
  end

  def test_refuses_a_non_ascii_path_unless_smtputf8_is_on
    error = assert_raises(MailSmtp::InvalidParameters) { strict.address_in("<üser@example.com>") }

    assert_equal "Non-ASCII path", error.message
    assert_equal "üser@example.com", utf8.address_in("<üser@example.com>")
  end

  def test_refuses_a_path_that_is_not_valid_utf8_under_smtputf8
    error = assert_raises(MailSmtp::InvalidParameters) { utf8.address_in("<b\xC3(d@example.com>".b) }

    assert_equal "Malformed UTF-8 path", error.message
  end

  # The socket hands up BINARY, and an application comparing or storing the mailbox
  # as text should not have to know that.
  def test_returns_a_utf8_mailbox_whatever_the_incoming_encoding
    assert_equal Encoding::UTF_8, strict.address_in("<a@example.com>".b).encoding
    assert_equal Encoding::UTF_8, loose.address_in("a@example.com".b).encoding
    assert_equal Encoding::UTF_8, utf8.address_in("<üser@example.com>".b).encoding
    assert_equal Encoding::UTF_8, strict.address_in("<>".b).encoding
  end

  private
    def strict
      @strict ||= MailSmtp::PathParser.new(strict: true, smtputf8: false)
    end

    def loose
      @loose ||= MailSmtp::PathParser.new(strict: false, smtputf8: false)
    end

    def utf8
      @utf8 ||= MailSmtp::PathParser.new(strict: true, smtputf8: true)
    end
end
