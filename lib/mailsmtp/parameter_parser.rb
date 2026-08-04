module MailSmtp
  # The ESMTP parameters trailing a MAIL FROM / RCPT TO path: each one is read only
  # when its extension is on, and the rest is refused. Configuration only — no IO.
  class ParameterParser
    # Each flag mirrors an EHLO advertisement, so nothing is accepted here that the
    # server did not offer. +auth_enabled+ is AUTH in any mode but +:disabled+.
    def initialize(max_message_size:, eight_bit_mime:, smtputf8:, auth_enabled:)
      @max_message_size = max_message_size
      @eight_bit_mime = eight_bit_mime
      @smtputf8 = smtputf8
      @auth_enabled = auth_enabled
    end

    # BODY= (RFC 6152), SMTPUTF8 (RFC 6531), SIZE= (RFC 1870), AUTH= (RFC 4954 §5),
    # each needing its extension on; whatever is left is refused 555 (RFC 1869 §6.1).
    def mail_from_extensions_in(parameters)
      extensions = {}

      if (declared = parameters[/\sSIZE=(\d+)\b/i, 1])
        # Base 10 explicitly: Integer("0100") would otherwise read as octal and
        # under-report the declared size, and Integer("08") would raise.
        declared = Integer(declared, 10)
        extensions[:declared_size] = declared
        if @max_message_size && declared > @max_message_size
          raise MessageTooLarge, "Declared #{declared} bytes, limit is #{@max_message_size}"
        end
      end

      if parameters.match?(/\sBODY=7BIT\b/i)
        raise InvalidParameters unless @eight_bit_mime
        extensions[:body_encoding] = :seven_bit
      elsif parameters.match?(/\sBODY=8BITMIME\b/i)
        raise InvalidParameters unless @eight_bit_mime
        extensions[:body_encoding] = :eight_bit_mime
      elsif parameters.match?(/\sBODY=\S+/i)
        raise InvalidParameters
      end

      if parameters.match?(/\sSMTPUTF8\b/i)
        raise InvalidParameters unless @smtputf8
        extensions[:smtputf8] = true
      end

      # "<>" is the client asserting no identity, kept as "" so it can never be
      # mistaken for a mailbox — an absent AUTH= leaves +auth_identity+ nil.
      if (asserted = parameters[/\sAUTH=(\S*)/i, 1])
        raise InvalidParameters unless @auth_enabled
        extensions[:auth_identity] = asserted == "<>" ? "" : auth_identity_in(asserted)
      end

      raise InvalidParameters if !@smtputf8 && !parameters.ascii_only?

      unhandled = parameters
        .gsub(/\sSIZE=\d+\b/i, "")
        .gsub(/\sBODY=(?:7BIT|8BITMIME)\b/i, "")
        .gsub(/\sSMTPUTF8\b/i, "")
        .gsub(/\sAUTH=\S*/i, "")
      raise_if_unhandled(unhandled)

      extensions
    end

    # A leftover that still parses as an ESMTP parameter is one we don't implement
    # (555); anything else — a second path, trailing junk — is a syntax error.
    def raise_if_unhandled(parameters)
      unhandled = parameters.strip
      raise ParametersNotRecognized if unhandled.match?(/\A\S+=/)
      raise InvalidParameters unless unhandled.empty?
    end

    private
      # xtext (RFC 4954 §5): printable US-ASCII bar "+" and "=", "+XX" escapes otherwise.
      # Decoding is how a control character would forge a line in whatever logs the claim.
      def auth_identity_in(value)
        raise InvalidParameters unless value.match?(/\A(?:[\x21-\x2a\x2c-\x3c\x3e-\x7e]|\+\h\h)+\z/)

        # Decoded over bytes, since an escape may name any octet.
        identity = value.b.gsub(/\+\h\h/) { |escape| escape[1, 2].hex.chr }.force_encoding(Encoding::UTF_8)
        raise InvalidParameters unless identity.valid_encoding? && (@smtputf8 || identity.ascii_only?)
        raise InvalidParameters if identity.match?(/[\x00-\x1f\x7f]/)

        identity
      end
  end
end
