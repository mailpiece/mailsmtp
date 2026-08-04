require_relative "test_helper"

class MailSmtp::DataReaderTest < MailSmtp::TestCase
  def test_readpartial_raises_service_unavailable_when_connection_drops_mid_data
    lines = [ "Subject: hi\r\n", "\r\n", "hello body content here!!\r\n" ]
    reader = MailSmtp::DataReader.new(max_message_size: nil) do
      raise MailSmtp::ServiceUnavailable, "Connection lost during DATA" if lines.empty?

      lines.shift
    end

    # A single readpartial must discover the drop (fill to maxlen), not return the
    # first line alone for short-read loops to treat as a complete message.
    assert_raises(MailSmtp::ServiceUnavailable) { reader.readpartial(8192) }
  end

  def test_readpartial_raises_eof_only_after_terminator
    lines = [ "Hi\r\n", ".\r\n" ]
    reader = MailSmtp::DataReader.new(max_message_size: nil) do
      line = lines.shift
      line == ".\r\n" ? nil : line
    end

    assert_equal "Hi\r\n", reader.readpartial(64)
    assert_raises(EOFError) { reader.readpartial(64) }
  end

  def test_readpartial_returns_chunks_until_terminator
    lines = [ "aa\r\n", "bb\r\n", ".\r\n" ]
    reader = MailSmtp::DataReader.new(max_message_size: nil) do
      line = lines.shift
      line == ".\r\n" ? nil : line
    end

    assert_equal "aa\r\n", reader.readpartial(4)
    assert_equal "bb\r\n", reader.readpartial(4)
    assert_raises(EOFError) { reader.readpartial(4) }
  end

  def test_drain_stops_on_ceiling_after_line_too_long
    lines = [
      "X-Long: #{"x" * 1200}\r\n",
      *Array.new(20) { "y" * 50 + "\r\n" }
      # no terminating "." — previously this could drain forever
    ]
    reader = MailSmtp::DataReader.new(max_message_size: 200, max_line_length: 1000) do
      lines.shift
    end

    assert_raises(MailSmtp::LineTooLong) { reader.read }
    reader.drain

    assert_predicate reader, :drain_ceiling_hit?
    assert_operator lines.size, :>, 0
    assert_instance_of MailSmtp::LineTooLong, reader.failure
  end

  def test_drain_uses_absolute_ceiling_when_max_message_size_is_nil
    chunk = ("z" * 1000) + "\r\n"
    # Enough lines to exceed DRAIN_BYTE_CEILING without a terminating "."
    remaining = (MailSmtp::DataReader::DRAIN_BYTE_CEILING / chunk.bytesize) + 5
    lines = Array.new(remaining) { chunk.dup }

    reader = MailSmtp::DataReader.new(max_message_size: nil, max_line_length: 2000) do
      lines.shift
    end

    reader.drain

    assert_predicate reader, :drain_ceiling_hit?
    assert_operator lines.size, :>, 0
  end

  def test_read_zero_returns_empty_string_without_consuming
    lines = [ "Hi\r\n", ".\r\n" ]
    reader = MailSmtp::DataReader.new(max_message_size: nil) do
      line = lines.shift
      line == ".\r\n" ? nil : line
    end

    assert_equal "", reader.read(0)
    assert_equal "Hi\r\n", reader.read
  end

  def test_prefixed_reader_read_zero_matches_data_reader
    inner = MailSmtp::DataReader.new(max_message_size: nil) { nil }
    reader = MailSmtp::PrefixedReader.new("PREFIX\r\n", inner)

    assert_equal "", reader.read(0)
    assert_equal "PREFIX\r\n", reader.read
  end
end
