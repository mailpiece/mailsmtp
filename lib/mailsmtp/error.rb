module MailSmtp
  class Error < RuntimeError
    class << self
      # +enhanced+ is an RFC 2034 / 3463 status like "5.3.4".
      def status(code, text, enhanced:)
        @code = code
        @text = text
        @enhanced = enhanced
      end

      def assert_status
        if code.nil? || text.nil? || enhanced.nil?
          raise "MailSmtp::Error subclass #{self} must declare status"
        end
      end

      def code
        if instance_variable_defined?(:@code)
          @code
        elsif superclass < Error
          superclass.code
        end
      end

      def text
        if instance_variable_defined?(:@text)
          @text
        elsif superclass < Error
          superclass.text
        end
      end

      def enhanced
        if instance_variable_defined?(:@enhanced)
          @enhanced
        elsif superclass < Error
          superclass.enhanced
        end
      end
    end

    def response
      self.class.assert_status
      "#{self.class.code} #{self.class.enhanced} #{self.class.text}"
    end

    # Whether DATA can still be resynchronized after this failure. False here, so the
    # body is drained to its terminating "." and the session continues; the subclasses
    # that override it end the connection with their reply instead.
    def unrecoverable? = false
  end
end
