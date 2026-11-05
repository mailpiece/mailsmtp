module MailSmtp
  module Limits
    # Deprecated: no DATA line length is enforced.
    MAX_TEXT_LINE_LENGTH = 1000
    # Default SIZE ceiling, and the absolute drain ceiling when SIZE is off.
    MAX_MESSAGE_SIZE = 10_485_760 # 10 MiB
  end
end
