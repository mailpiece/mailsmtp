module MailSmtp
  module Limits
    # RFC 5321 §4.5.3.1.6: text line octets, including the CRLF.
    MAX_TEXT_LINE_LENGTH = 1000
    # Default SIZE ceiling, and the absolute drain ceiling when SIZE is off.
    MAX_MESSAGE_SIZE = 10_485_760 # 10 MiB
  end
end
