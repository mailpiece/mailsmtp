module MailSmtp
  # Shared listener harness for integration tests: start/stop, sockets, and the
  # common Server subclasses / TLS doubles used across AUTH, DATA, TLS, etc.
  class ServerIntegrationTest < TestCase
    # The per-IP cap the connection and PROXY tests configure. Two, so that
    # filling it and going one past it are different sockets.
    MAX_PER_IP = 2

    def setup
      @servers = []
      @sockets = []
      @listeners = []
      @ports = {}
    end

    def teardown
      @sockets.each { |socket| close(socket) }
      @servers.each(&:stop)
      @listeners.each { |listener| close(listener) }
    end

    class ReceivingServer < MailSmtp::Server
      attr_reader :received, :last_body_encoding, :last_smtputf8, :mail_from_calls, :receive_count

      def initialize(**)
        super
        @mail_from_calls = []
        @receive_count = 0
      end

      # The engine hands over the mailbox already unwrapped from its path.
      def mail_from(_session, address)
        @mail_from_calls << address
        address
      end

      def rcpt_to(_session, address)
        address
      end

      def receive(session, io)
        @receive_count += 1
        @last_body_encoding = session.envelope.body_encoding
        @last_smtputf8 = session.envelope.smtputf8
        @received = {
          from: session.envelope.from,
          to: session.envelope.to.dup,
          data: io.read
        }
      end
    end

    # Records the DATA-phase notifications in the order the engine fires them, so a
    # refactor that drops one is caught rather than passing quietly.
    class HookRecordingServer < ReceivingServer
      attr_reader :calls, :phase_at_start, :headers_seen_body

      def initialize(**)
        super
        @calls = []
      end

      def receiving_started(session)
        @calls << :receiving_started
        @phase_at_start = session.phase
      end

      def headers_received(session)
        @calls << :headers_received
        @headers_seen_body = session.envelope.to.dup
      end

      def receive(session, io)
        @calls << :receive
        super
      end
    end

    # The README's first recommendation: hand the reader straight to IO.copy_stream.
    class CopyStreamServer < ReceivingServer
      attr_reader :copied

      def receive(_session, io)
        destination = StringIO.new(+"", "wb")
        IO.copy_stream(io, destination)
        @copied = destination.string
      end
    end

    class DeclaredSizeServer < ReceivingServer
      attr_reader :seen_declared_size

      def receive(session, io)
        @seen_declared_size = session.envelope.declared_size
        super
      end
    end

    class StreamingServer < ReceivingServer
      attr_reader :streamed, :read_iterations

      def receive(session, io)
        @streamed = +""
        @read_iterations = 0
        while (chunk = io.read(64))
          @read_iterations += 1
          break if @read_iterations > 5_000
          @streamed << chunk
        end
        @last_body_encoding = session.envelope.body_encoding
        @last_smtputf8 = session.envelope.smtputf8
        @received = {
          from: session.envelope.from,
          to: session.envelope.to.dup,
          data: @streamed.dup
        }
      end
    end

    class CapturingFailureServer < ReceivingServer
      attr_reader :read_error, :persisted_body

      def receive(_session, io)
        @persisted_body = io.read
      rescue MailSmtp::Error => e
        @read_error = e
        @persisted_body = nil
        raise
      end
    end

    class ClosedCheckServer < ReceivingServer
      attr_reader :saw_closed

      def receive(session, io)
        @saw_closed = io.closed?
        super
      end
    end

    class FakeTls
      def start(io)
        io.define_singleton_method(:ssl_version) { "TLSv1.3" }
        io.define_singleton_method(:cipher) { [ "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256, 256 ] }
        io
      end
    end

    class OpensslTls
      def initialize(context)
        @context = context
      end

      def start(io)
        ssl = OpenSSL::SSL::SSLSocket.new(io, @context)
        ssl.sync_close = true
        ssl.accept
      end
    end

    class SlowTls
      def initialize(seconds)
        @seconds = seconds
      end

      def start(io)
        sleep @seconds
        FakeTls.new.start(io)
      end
    end

    class BlockingPrintTls
      def start(io)
        FakeTls.new.start(io)
        io.define_singleton_method(:print) { |*_args, **_kwargs| sleep 5 }
        io
      end
    end

    class RelayDenied < MailSmtp::Error
      status 550, "Relay denied", enhanced: "5.7.1"
    end

    class PolicyServer < ReceivingServer
      def mail_from(_session, _address)
        raise RelayDenied
      end
    end

    class TlsRecordingServer < ReceivingServer
      attr_reader :tls_version, :tls_cipher, :encrypted

      def helo(session, _name)
        @tls_version = session.tls_version
        @tls_cipher = session.tls_cipher
        @encrypted = session.encrypted?
      end
    end

    class AuthedServer < ReceivingServer
      attr_reader :authenticated_as

      def authenticate(_session, username:, password:, authorization_id: "")
        raise MailSmtp::AuthenticationFailed unless username == "user" && password == "secret"
        @authenticated_as = username
        username
      end
    end

    class PlainOnlyAuthServer < AuthedServer
      def auth_mechanisms(_session)
        %w[ PLAIN ]
      end
    end

    class LifecycleServer < ReceivingServer
      attr_reader :connected_count, :disconnected_count

      def initialize(**)
        super
        @connected_count = 0
        @disconnected_count = 0
        @lifecycle_mutex = Mutex.new
      end

      def connected(_session)
        @lifecycle_mutex.synchronize { @connected_count += 1 }
      end

      def disconnected(_session)
        @lifecycle_mutex.synchronize { @disconnected_count += 1 }
      end
    end

    class TlsReaderOverrideServer < ReceivingServer
      attr_reader :tls_reader_used

      def tls
        @tls_reader_used = true
        FakeTls.new
      end
    end

    class NilProcessLineServer < ReceivingServer
      def process_line(session, line)
        if line.match?(/\ANOOP/i)
          nil
        else
          super
        end
      end
    end

    class ProxyRecordingServer < ReceivingServer
      attr_reader :proxy_data

      def proxy(_session, proxy_data)
        @proxy_data = proxy_data
      end
    end

    # Slow enough that a forced stop always lands mid-command, and counts the
    # calls so a test can tell whether the pipeline behind it also ran.
    class SlowCommandServer < ReceivingServer
      COMMAND_SECONDS = 1

      attr_reader :process_line_calls

      def initialize(**)
        super
        @process_line_calls = 0
      end

      def process_line(session, line)
        @process_line_calls += 1
        sleep COMMAND_SECONDS
        super
      end
    end

    # Swallows the one StopConnection it is ever sent, so the drain has to
    # abandon it instead of waiting.
    class UnstoppableServer < ReceivingServer
      IGNORED_STOP_SECONDS = 3

      def process_line(session, line)
        sleep IGNORED_STOP_SECONDS
        super
      rescue Exception
        sleep IGNORED_STOP_SECONDS
        ""
      end
    end

    # A refused connection must not reach anything a connection thread does, and
    # building the session is the first of those things.
    class SessionCountingServer < ReceivingServer
      attr_reader :built_sessions

      def initialize(**)
        super
        @built_sessions = 0
        @sessions_mutex = Mutex.new
      end

      def build_session
        @sessions_mutex.synchronize { @built_sessions += 1 }
        super
      end
    end

    # Wraps a real listener and fails +accept+ a fixed number of times first, so the
    # acceptor's backoff runs against a socket that is otherwise genuine.
    class FailingListener
      def initialize(listener, error:, failures:)
        @listener = listener
        @error = error
        @remaining = failures
        @mutex = Mutex.new
      end

      def accept
        failing = @mutex.synchronize do
          if @remaining.positive?
            @remaining -= 1
            true
          else
            false
          end
        end

        raise @error if failing
        @listener.accept
      end

      def addr(...) = @listener.addr(...)
      def close = @listener.close
      def closed? = @listener.closed?
    end

    class CustomSession < MailSmtp::Session
    end

    class CustomSessionServer < ReceivingServer
      attr_reader :used_custom_session

      def build_session
        CustomSession.new
      end

      def receive(session, io)
        @used_custom_session = session.is_a?(CustomSession)
        super
      end
    end

    private
      def start_server(**overrides)
        start(MailSmtp::Server.new(**server_options(**overrides)))
      end

      # The listener is already bound, so a client can connect the moment this returns —
      # there is nothing to probe for, and no port to lose between binding and listening.
      def start(server)
        server.start
        @servers << server
        server
      end

      # The test's own listener, bound on port 0 and handed to the server. Pass +port:+
      # instead only where a test is about the host/port path itself.
      def listener
        @listener ||= bind_listener
      end

      def bind_listener
        TCPServer.new("127.0.0.1", 0).tap do |socket|
          @listeners << socket
          # Remembered here so the port survives the +stop+ that closes the socket.
          @ports[socket] = socket.addr(:numeric)[1]
        end
      end

      def port
        port_of(listener)
      end

      def port_of(listener)
        @ports.fetch(listener)
      end

      def server_options(port: nil, listeners: nil, max_connections_per_ip: nil, auth: :disabled,
        starttls: :optional, max_message_size: nil, **extras)
        listen = port ? { host: "127.0.0.1", port: port } : { listeners: listeners || [ listener ] }
        # Quiet by default, but the two options are exclusive: a test that supplies its
        # own logger has already set the level on it.
        logging = extras.key?(:logger) ? {} : { logger_severity: Logger::FATAL }

        {
          tls: nil,
          max_connections: 50,
          max_processings: 10,
          max_connections_per_ip: max_connections_per_ip,
          auth: auth,
          starttls: starttls,
          max_message_size: max_message_size
        }.merge(logging).merge(listen).merge(extras)
      end

      def with_smtp(port)
        smtp = Net::SMTP.new("127.0.0.1", port)
        smtp.disable_starttls
        smtp.start("test.client.example") { yield smtp }
      end

      def connect(port)
        TCPSocket.new("127.0.0.1", port).tap { |socket| @sockets << socket }
      end

      def close(socket)
        socket.close
      rescue StandardError
        # already gone
      end

      def wait_until_idle(server, timeout: 5)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

        sleep 0.01 while server.connections? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      end
  end
end
