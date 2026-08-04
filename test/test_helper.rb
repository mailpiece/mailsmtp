$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mailsmtp"
require "socket"
require "openssl"
require "net/smtp"
require "logger"
require "base64"
require "stringio"

module MailSmtp
  class TestCase < Minitest::Test
    private
      def read_smtp_response(socket)
        loop do
          line = socket.gets
          break line if line.nil? || line[3] != "-"
        end
      end

      def read_smtp_lines(socket)
        [].tap do |lines|
          loop do
            line = socket.gets
            break if line.nil?
            lines << line.chomp
            break if line[3] != "-"
          end
        end
      end

      def self_signed_context(cn: "mailsmtp.test", serial: 1)
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = serial
        name = OpenSSL::X509::Name.parse("/CN=#{cn}")
        cert.subject = name
        cert.issuer = name
        cert.public_key = key.public_key
        cert.not_before = Time.now - 60
        cert.not_after = Time.now + 3600
        cert.sign(key, OpenSSL::Digest.new("SHA256"))

        OpenSSL::SSL::SSLContext.new.tap do |ctx|
          ctx.cert = cert
          ctx.key = key
        end
      end

      def ssl_starttls_client(socket)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl = OpenSSL::SSL::SSLSocket.new(socket, ctx)
        ssl.sync_close = true
        ssl.connect
        ssl
      end
  end
end

require_relative "support/server_integration"
