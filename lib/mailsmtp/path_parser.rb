module MailSmtp
  # Envelope path framing (RFC 5321 §4.1.2): splits a path from the ESMTP parameters
  # behind it, and unwraps it to a mailbox. Configuration only — no session, no IO.
  class PathParser
    # RFC 5321 §4.5.3.1.3: a path is at most 256 octets, brackets included. The
    # 64-octet local part (§4.5.3.1.1) is not: Gmail's "…+caf_=…" runs 66–72.
    MAX_PATH_LENGTH = 256

    # +strict+ demands the angle brackets; +smtputf8+ admits a non-ASCII mailbox
    # (RFC 6531 §3.4), which the engine otherwise refuses on the application's behalf.
    def initialize(strict:, smtputf8:)
      @strict = strict
      @smtputf8 = smtputf8
    end

    # RFC 5321 §4.1.2: the path ends at its closing ">", parameters follow. Scanning
    # the whole tail let <"pay SIZE=1 me"@example.com> declare a 1-octet message.
    def split_from_parameters(data)
      if bracketed_path?(data)
        split_at_closing_bracket(data)
      else
        split_at_first_space(data)
      end
    end

    # Framing only (RFC 5321 §4.1.2): unwrap brackets and source route, return
    # the mailbox unrepaired. Brackets required unless +strict: false+.
    def address_in(data)
      if bracketed_path?(data)
        bracketed_path_in(data)
      else
        bare_path_in(data)
      end
    end

    private
      # Under +strict+ a path is bracketed or it is not a path at all, so an unbracketed
      # tail earns its 501 in +address_in+ rather than being guessed at here.
      def bracketed_path?(data)
        @strict || data.start_with?("<")
      end

      # With no ">" there is no path to delimit, so the tail is all parameters and the
      # 501 the path is about to earn still lands behind the parameter replies.
      def split_at_closing_bracket(data)
        if (closing = data.index(">"))
          [ data[..closing], data[(closing + 1)..] ]
        else
          [ data, data ]
        end
      end

      # The boundary for a bare path is the first space, so the client's spacing says
      # where the address ends — "MAIL FROM:a=b@example.com" is an address, not a 555.
      def split_at_first_space(data)
        if (boundary = data.index(/\s/))
          [ data[...boundary], data[boundary..] ]
        else
          [ data, "" ]
        end
      end

      def bracketed_path_in(data)
        raise InvalidParameters, "Malformed path" unless data.match?(/\A<[^<>]*>\z/)
        raise InvalidParameters, "Path too long" if data.bytesize > MAX_PATH_LENGTH

        path = encoded_path_in(data)[1..-2].strip
        if path.empty?
          # The null sender is a literally empty <>, and nothing else may become
          # one — not "< >", and not a source route with no mailbox after it.
          raise InvalidParameters, "Malformed path" unless data == "<>"
          path
        else
          mailbox_in(path)
        end
      end

      # A bare path is the mailbox itself, so a bracket in it is malformed, not framing.
      # Nothing comes back empty: the null sender is "<>", never unbracketed.
      def bare_path_in(data)
        raise InvalidParameters, "Malformed path" if data.empty? || data.match?(/[<>]/)
        raise InvalidParameters, "Path too long" if data.bytesize > MAX_PATH_LENGTH

        mailbox_in(encoded_path_in(data))
      end

      # An internationalized mailbox rides on SMTPUTF8 (RFC 6531 §3.4) — the engine
      # promises the application ASCII envelope strings without it, and valid UTF-8
      # ones with it, rather than leaving bad bytes to fail in whatever downstream
      # compares, stores, or serializes the address. Either way what it hands over is
      # a UTF-8 String, never the BINARY the socket read.
      def encoded_path_in(data)
        path = data.dup.force_encoding(Encoding::UTF_8)

        if @smtputf8
          raise InvalidParameters, "Malformed UTF-8 path" unless path.valid_encoding?
        else
          raise InvalidParameters, "Non-ASCII path" unless path.ascii_only?
        end

        path
      end

      # A quoted-string local part ("a b"@example.com) is legal RFC 5321 and refused
      # here: accepting it makes every consumer need a quoted-string scanner too.
      def mailbox_in(path)
        mailbox = strip_source_route(path)
        raise InvalidParameters, "Quoted local part" if mailbox.start_with?('"')
        mailbox
      end

      # RFC 5321 §3.6.1: ignore a source route — honoring it would make us a relay for
      # whoever wrote it. A route with nothing after it cannot forge the null sender.
      def strip_source_route(path)
        mailbox = path.sub(/\A@[^:]*:/, "")
        raise InvalidParameters, "Malformed path" if mailbox.empty?
        mailbox
      end
  end
end
