module MailSmtp
  # Every SMTP reply carries an RFC 2034 enhanced status code.

  # 421 — connection is being dropped: too busy, timed out, or abusing the protocol
  class ServiceUnavailable < Error
    status 421, "Service not available, closing transmission channel", enhanced: "4.3.2"
  end

  # 421 — the peer is already gone before any reply could reach it, e.g. a mid-DATA disconnect.
  class ConnectionLost < ServiceUnavailable
  end

  # 451 — the app hit an unexpected error handling an otherwise-valid message
  class LocalError < Error
    status 451, "Requested action aborted: local error in processing", enhanced: "4.3.0"
  end

  # 452 — envelope has more recipients than we allow in one transaction
  class TooManyRecipients < Error
    status 452, "Requested action not taken: too many recipients", enhanced: "4.5.3"
  end

  # 500 — command verb not recognized
  class CommandNotRecognized < Error
    status 500, "Syntax error, command unrecognized", enhanced: "5.5.1"
  end

  # 500 — a DATA body line exceeded the RFC 5321 text-line limit
  class LineTooLong < Error
    status 500, "Line too long", enhanced: "5.5.2"
  end

  # 502 — command recognized but not implemented (VRFY's cousins EXPN/HELP)
  class CommandNotImplemented < Error
    status 502, "Command not implemented", enhanced: "5.5.1"
  end

  # 500 — a second command arrived pipelined ahead of its reply, which we don't support
  class PipeliningNotSupported < Error
    status 500, "Pipelining is not supported; commands must be sent one at a time", enhanced: "5.5.2"
  end

  # 501 — a command parameter we don't support (e.g. SMTPUTF8)
  class InvalidParameters < Error
    status 501, "Syntax error in parameters or arguments", enhanced: "5.5.4"
  end

  # 503 — command arrived out of the expected HELO/AUTH/MAIL/RCPT/DATA sequence
  class BadSequence < Error
    status 503, "Bad sequence of commands", enhanced: "5.5.1"
  end

  # 504 — an AUTH mechanism we don't offer (RFC 4954 §4); only PLAIN and LOGIN
  class AuthenticationTypeNotSupported < Error
    status 504, "Unrecognized authentication type", enhanced: "5.5.4"
  end

  # 530 — TLS is required and the client hasn't issued STARTTLS yet
  class EncryptionRequired < Error
    status 530, "Must issue a STARTTLS command first", enhanced: "5.7.0"
  end

  # 530 — AUTH is required and the client hasn't authenticated yet
  class AuthenticationRequired < Error
    status 530, "Authentication required", enhanced: "5.7.0"
  end

  # 535 — AUTH credentials were rejected
  class AuthenticationFailed < Error
    status 535, "Authentication credentials invalid", enhanced: "5.7.8"
  end

  # 550 — DATA contained a bare LF (SMTP smuggling / non-CRLF line endings)
  # Unrecoverable: a sender that frames one line without CRLF may never send the
  # CRLF "." a drain would wait for, and its framing is what smuggling exploits.
  class BareNewline < Error
    status 550, "Bare <LF> disallowed; lines must end with <CRLF>", enhanced: "5.5.2"

    def unrecoverable? = true
  end

  # 550 — DATA contained a CR that wasn't part of a CRLF (RFC 5321 §2.3.8)
  class BareCarriageReturn < Error
    status 550, "Bare <CR> disallowed; lines must end with <CRLF>", enhanced: "5.5.2"

    def unrecoverable? = true
  end

  # 552 — declared or actual message size exceeds the configured limit
  # Unrecoverable by RFC 5321 §4.5.3.1.7, which lets the server close after 552.
  class MessageTooLarge < Error
    status 552, "Requested mail action aborted: exceeded storage allocation", enhanced: "5.3.4"

    def unrecoverable? = true
  end

  # 555 — an ESMTP parameter we don't implement (RFC 1869 §6.1)
  class ParametersNotRecognized < Error
    status 555, "MAIL FROM/RCPT TO parameters not recognized or not implemented", enhanced: "5.5.4"
  end
end
