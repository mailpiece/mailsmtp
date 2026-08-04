module MailSmtp
  # Per-connection state for one SMTP conversation — subclass it via
  # Server#build_session. Message bytes never live here; DATA passes a +DataReader+.
  class Session
    class Envelope
      # +auth_identity+ is the decoded MAIL FROM AUTH= identity (RFC 4954 §5) — nil
      # when the client sent none, "" for the "<>" form. A claim, never a fact.
      attr_accessor :from, :body_encoding, :smtputf8, :declared_size, :auth_identity
      attr_reader :to

      def initialize
        @to = []
      end

      # The null reverse-path <> (RFC 5321 §4.5.5) arrives as an empty +from+, so the
      # sender stays a String; before MAIL FROM +from+ is nil, not a null sender.
      def null_sender?
        from == ""
      end
    end

    attr_accessor :phase,
      :local_ip, :remote_ip, :helo, :greeting, :banner,
      :connected_at, :encrypted_at, :authenticated_at,
      :authorization_id, :authentication_id, :requested_authorization_id,
      :auth_login_username,
      :exceptions, :auth_failures, :proxy, :close_after_reply,
      :tls_version, :tls_cipher
    attr_reader :envelope

    def initialize
      @exceptions = 0
      @auth_failures = 0
      @proxy = nil
      @close_after_reply = false
      @tls_version = nil
      @tls_cipher = nil
      reset
      @phase = :helo
    end

    # Clears the per-message state — envelope and command sequence — while
    # keeping the connection and its authentication.
    def reset
      @phase = :ready
      @envelope = Envelope.new
      @auth_login_username = nil
    end

    # Drop identity asserted before STARTTLS (RFC 3207 §4.2).
    def reset_authentication
      @authenticated_at = nil
      @authorization_id = nil
      @authentication_id = nil
      @requested_authorization_id = nil
      @auth_login_username = nil
    end

    def authenticated?
      !authenticated_at.nil?
    end

    def encrypted?
      !encrypted_at.nil?
    end
  end
end
