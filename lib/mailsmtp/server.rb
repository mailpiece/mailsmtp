require "socket"
require "openssl"
require "base64"
require "logger"
require "ipaddr"
require "timeout"

module MailSmtp
  # A thread-per-connection SMTP *server* driving RFC 5321, with domain policy in
  # the subclass hooks (README). STARTTLS drops buffered plaintext (CVE-2011-0411).
  class Server
    AUTH_POLICIES = %i[ disabled required ].freeze
    STARTTLS_POLICIES = %i[ optional required ].freeze

    # RFC 4954 §4: AUTH LOGIN prompts with base64 "Username:" then "Password:".
    AUTH_LOGIN_USERNAME_PROMPT = "334 #{Base64.strict_encode64("Username:")}".freeze
    AUTH_LOGIN_PASSWORD_PROMPT = "334 #{Base64.strict_encode64("Password:")}".freeze

    # One read syscall's worth of socket bytes.
    READ_CHUNK_BYTES = 4096
    # How long a read may park when the socket has nothing ready, so a shutdown
    # is still noticed by a session that is only waiting.
    READ_WAIT_SECONDS = 1
    # Short write budget for a 421 abort after a normal write already timed out,
    # so we do not stack another full +write_timeout+ before dropping the socket.
    ABORT_REPLY_WRITE_TIMEOUT = 2
    private_constant :READ_CHUNK_BYTES, :READ_WAIT_SECONDS, :ABORT_REPLY_WRITE_TIMEOUT

    # Ceiling on bytes held behind a line that has not been terminated yet.
    PENDING_INPUT_LIMIT = 1_048_576
    # RFC 5321 §4.5.3.2.7: servers should wait at least 5 minutes for the next
    # client command. (The earlier §4.5.3.2.1–.6 times are client-side.)
    READ_TIMEOUT = 300
    # Postfix's smtpd_min_data_rate (bytes per second): past +read_timeout+, DATA
    # must keep up this rate, so a line every few seconds cannot hold a slot.
    MIN_DATA_RATE = 500
    WRITE_TIMEOUT = 30
    HANDSHAKE_TIMEOUT = 30
    MAX_PROCESSINGS_WAIT = 30
    MAX_RECIPIENTS = 100
    MAX_MESSAGE_SIZE = Limits::MAX_MESSAGE_SIZE
    # Absolute ceiling so idle resets on each line cannot stretch a session forever.
    MAX_SESSION_DURATION = 1800
    MAX_AUTH_FAILURES = 3
    MAX_EXCEPTIONS = 20
    # Postfix's smtpd_error_sleep_time: the pause before each error reply once a
    # session is past +error_sleep_after+ errors.
    ERROR_SLEEP_TIME = 1
    # Postfix's STRESS_README: with +stress_threshold+ of +max_connections+ admitted,
    # the idle and handshake timeouts drop to STRESS_TIMEOUT (unless configured lower)
    # and one protocol error ends a session, so a flood frees slots fast.
    STRESS_TIMEOUT = 10
    STRESS_MAX_EXCEPTIONS = 1
    # Only for the logger this class builds for itself — a supplied +logger+ brings
    # its own level.
    LOGGER_SEVERITY = Logger::INFO
    # RFC 5321 §4.5.3.1.4 (octets, including the CRLF).
    MAX_COMMAND_LINE_LENGTH = 512
    MAX_TEXT_LINE_LENGTH = Limits::MAX_TEXT_LINE_LENGTH
    # RFC 4954 §4: AUTH base64 responses (commands and continuations) may be
    # up to 12288 octets — not the 512-octet SMTP command-line ceiling.
    MAX_AUTH_LINE_LENGTH = 12_288

    # RFC 5322 header specials: parens (comments), backslash/quote (quoted strings),
    # angle brackets and "@" (addr-spec), ";" (Received date), space (token boundary).
    HELO_SPECIALS = ' <>()\\";@'.freeze
    # Everything outside printable US-ASCII, plus HELO_SPECIALS. Not
    # fixed-encoding, so it applies to a BINARY subject byte by byte.
    HELO_UNSAFE = /[^\x20-\x7e]|[#{Regexp.escape(HELO_SPECIALS)}]/
    # For an SMTPUTF8 HELO: UTF-8 minus control/format characters and the non-ASCII
    # spaces and separators that smuggle whitespace. Only for a valid_encoding? string.
    HELO_UNSAFE_UTF8 =
      /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}\p{Cn}\p{Co}]|[#{Regexp.escape(HELO_SPECIALS)}]/
    private_constant :HELO_SPECIALS, :HELO_UNSAFE, :HELO_UNSAFE_UTF8

    # A failed accept is classified, not counted. Running out of descriptors is the
    # usual reason a public MX cannot accept, and it clears itself as connections
    # close, so the listener backs off and waits it out instead of counting toward a
    # stop it never comes back from.
    ACCEPT_BACKOFF_ERRORS = [ Errno::EMFILE, Errno::ENFILE, Errno::ENOBUFS, Errno::ENOMEM ].freeze
    # This connection died between the kernel queueing it and us taking it. Nothing
    # is wrong with the listener, so there is nothing to wait for either.
    ACCEPT_RETRY_ERRORS = [ Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR ].freeze
    MIN_ACCEPT_BACKOFF = 0.005
    MAX_ACCEPT_BACKOFF = 1
    private_constant :ACCEPT_BACKOFF_ERRORS, :ACCEPT_RETRY_ERRORS,
      :MIN_ACCEPT_BACKOFF, :MAX_ACCEPT_BACKOFF

    # Floor on the unwind of a forced stop before the socket is reset and the thread
    # abandoned — never zero, even for +stop(drain_for: 0)+.
    MIN_UNWIND_GRACE = 1
    private_constant :MIN_UNWIND_GRACE

    # PROXY protocol v1 §2.1: the transport token names the address family, and
    # "UNKNOWN" means the sender is declaring nothing at all.
    PROXY_TRANSPORTS = { "TCP4" => :ipv4?, "TCP6" => :ipv6? }.freeze
    PROXY_UNSPECIFIED = "UNKNOWN".freeze
    # <source-ip> <dest-ip> <source-port> <dest-port>, always all four.
    PROXY_ENDPOINT_FIELDS = 4
    # Bare literals only. IPAddr would also take "10.0.0.0/8" and "fe80::1%eth0",
    # either of which resolves to an address the header never actually named.
    PROXY_ADDRESS = /\A[0-9a-f.:]+\z/i
    PROXY_PORT = /\A[0-9]+\z/
    private_constant :PROXY_TRANSPORTS, :PROXY_UNSPECIFIED, :PROXY_ENDPOINT_FIELDS,
      :PROXY_ADDRESS, :PROXY_PORT

    # Raised into the acceptor threads by +stop+, and deliberately a StandardError
    # where StopConnection is an Exception: an acceptor runs no application code, so
    # the only rescue standing between the raise and the acceptor's own +rescue
    # StopService+ is ours.
    StopService = Class.new(RuntimeError)
    private_constant :StopService

    # Raised into a connection thread by a forced +stop+, which may be executing
    # application code — +receive+ above all, where a storage write is usually
    # wrapped in +rescue StandardError+. An Exception so that rescue cannot swallow
    # the shutdown and leave the drain burning its whole grace before the socket is
    # reset. Public for the same reason: an application that does see one has to be
    # able to name it to re-raise it.
    StopConnection = Class.new(Exception)

    # Raised by the PROXY field readers and turned into the one 421 where the
    # header is assembled, so each field can refuse without repeating the reason.
    UnusableProxyEndpoint = Class.new(RuntimeError)
    private_constant :UnusableProxyEndpoint

    # The caps an application is held to and has to agree with: the capacity an
    # operator watches alongside +connections_count+, and the two ceilings the engine
    # enforces around its own policy hooks — SIZE as EHLO advertises it, and the
    # recipient limit +rcpt_to+ is called under. Every other option is engine
    # behavior with no second reader.
    attr_reader :max_connections, :max_connections_per_ip, :max_processings,
      :max_message_size, :max_recipients
    # Reassign between STARTTLS negotiations to hot-swap certificates (e.g. ACME).
    # Engine paths call +#tls+ (not +@tls+) so an overridden reader is honored.
    attr_accessor :tls

    # +hosts+/+ports+ take arrays or comma-separated strings and expand to every
    # host×port pair. +max_message_size+ applies while DATA is read, not to +drain+.
    def initialize(tls:, max_connections:, max_processings:, auth:, starttls:,
      host: nil, port: nil, hosts: nil, ports: nil, listeners: nil,
      max_connections_per_ip: nil, eight_bit_mime: false, smtputf8: false,
      pipelining: false, proxy_hosts: [], add_received: false,
      forbid_bare_newline: true, strict_path: true,
      max_message_size: MAX_MESSAGE_SIZE, max_recipients: MAX_RECIPIENTS,
      max_processings_wait: MAX_PROCESSINGS_WAIT,
      read_timeout: READ_TIMEOUT, write_timeout: WRITE_TIMEOUT,
      min_data_rate: MIN_DATA_RATE,
      handshake_timeout: HANDSHAKE_TIMEOUT,
      max_session_duration: MAX_SESSION_DURATION,
      max_auth_failures: MAX_AUTH_FAILURES,
      max_exceptions: MAX_EXCEPTIONS,
      error_sleep_after: nil, error_sleep_time: ERROR_SLEEP_TIME, stress_threshold: nil,
      max_messages_per_ip: nil, max_tls_sessions_per_ip: nil, max_auth_attempts_per_ip: nil,
      pending_input_limit: PENDING_INPUT_LIMIT,
      logger: nil, logger_severity: nil)
      validate_options(tls: tls, auth: auth, starttls: starttls, max_connections: max_connections,
        max_processings: max_processings, max_connections_per_ip: max_connections_per_ip,
        max_recipients: max_recipients, max_auth_failures: max_auth_failures,
        max_exceptions: max_exceptions, min_data_rate: min_data_rate,
        error_sleep_after: error_sleep_after, error_sleep_time: error_sleep_time, stress_threshold: stress_threshold,
        max_messages_per_ip: max_messages_per_ip,
        max_tls_sessions_per_ip: max_tls_sessions_per_ip, max_auth_attempts_per_ip: max_auth_attempts_per_ip,
        eight_bit_mime: eight_bit_mime, smtputf8: smtputf8, logger: logger, logger_severity: logger_severity)

      @listeners = Array(listeners)
      @addresses = listen_addresses_in(hosts || host, ports || port)

      @tls = tls
      @max_connections = max_connections
      @max_connections_per_ip = max_connections_per_ip
      @max_processings = max_processings
      @max_processings_wait = max_processings_wait
      @auth = auth
      @starttls = starttls
      @eight_bit_mime = eight_bit_mime
      @smtputf8 = smtputf8
      @pipelining = pipelining
      @forbid_bare_newline = forbid_bare_newline
      @proxy_hosts = Array(proxy_hosts).map { |entry| IPAddr.new(entry) }
      @add_received = add_received
      @max_message_size = max_message_size
      @max_recipients = max_recipients
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      @min_data_rate = min_data_rate
      # Always finite, and independent of +read_timeout+ (which may be nil). +Timeout+
      # cannot interrupt OpenSSL's blocking accept, so +IO#timeout+ is set around it.
      @handshake_timeout = handshake_timeout || HANDSHAKE_TIMEOUT
      @max_session_duration = max_session_duration
      @max_auth_failures = max_auth_failures
      @max_exceptions = max_exceptions
      @error_sleep_after = error_sleep_after
      @error_sleep_time = error_sleep_time
      @stress_threshold = stress_threshold
      @max_messages_per_ip = max_messages_per_ip
      @max_tls_sessions_per_ip = max_tls_sessions_per_ip
      @max_auth_attempts_per_ip = max_auth_attempts_per_ip
      @message_rates = RateLimiter.new
      @tls_session_rates = RateLimiter.new
      @auth_attempt_rates = RateLimiter.new
      @pending_input_limit = pending_input_limit

      # The envelope grammar is settled once, from the same switches EHLO advertises.
      @path_parser = PathParser.new(strict: strict_path, smtputf8: smtputf8)
      @parameter_parser = ParameterParser.new(max_message_size: max_message_size,
        eight_bit_mime: eight_bit_mime, smtputf8: smtputf8, auth_enabled: auth != :disabled)

      @stdout_logger = logger || build_default_logger(logger_severity || LOGGER_SEVERITY)

      @connection_threads = []
      @connection_ips = {}
      @processing_threads = []
      @admitted = 0
      @slot_mutex = Mutex.new
      @slot_released = ConditionVariable.new
      @shutdown = false
      @tcp_servers = []
      @acceptor_threads = []
    end

    def start
      raise "Cannot start: this server is already listening" unless stopped?

      @shutdown = false
      @tcp_servers = @listeners.any? ? claimed_listeners : @addresses.map { |host, port| TCPServer.new(host, port) }
      attach_acceptors
    end

    def stop(drain_for: 2)
      @shutdown = true

      acceptors = @acceptor_threads.dup
      @slot_mutex.synchronize do
        acceptors.each { |thread| thread.raise(StopService) }
      end
      # A stop this soon after start can be delivered before an acceptor thread ever
      # entered its loop, so settle the listeners here rather than in the thread.
      acceptors.each { |thread| joined?(thread, nil) }
      close_listeners
      drain_connections(drain_for)
    end

    def stopped?
      @acceptor_threads.empty?
    end

    def connections_count
      @connection_threads.size
    end

    def connections?
      connections_count.positive?
    end

    def processings_count
      @processing_threads.size
    end

    # Whether admissions have reached +stress_threshold+ of +max_connections+. Public
    # so an application can tighten its own limits while it holds.
    def stressed?
      @stress_threshold && @admitted >= max_connections * @stress_threshold
    end

    # The configured host:port pairs — or, for supplied +listeners+, the addresses
    # they are really bound to.
    def addresses
      @addresses.map { |host, port| "#{host}:#{port}" }
    end

    # Override to customize the opt-in Received header (+add_received: true+).
    def received_header(session)
      protocol = session.encrypted? ? (session.authenticated? ? "ESMTPSA" : "ESMTPS") : "ESMTP"
      helo = session.helo.to_s
      helo = helo.empty? ? "unknown" : ascii_only_helo(session, helo)
      "Received: from #{helo} (unknown [#{session.remote_ip}]) " \
        "by #{session.greeting} with #{protocol}; #{Time.now.utc.strftime("%a, %d %b %Y %H:%M:%S +0000")}\r\n"
    end

    # Optional: inspect or replace PROXY data after a valid PROXY line.
    def proxy(session, proxy_data)
      proxy_data
    end

    def log(session, severity, msg, err: nil)
      if session.respond_to?(:remote_ip) && session.remote_ip
        msg = "[#{session.remote_ip}] #{msg}"
      end

      case severity
      when Logger::FATAL
        @stdout_logger.fatal(msg)
        Array(err&.backtrace).each { |line| @stdout_logger.fatal(line) }
      when Logger::ERROR
        @stdout_logger.error(msg)
      when Logger::WARN
        @stdout_logger.warn(msg)
      when Logger::INFO
        @stdout_logger.info(msg)
      else
        @stdout_logger.debug(msg)
      end
    end

    def connected(session)
    end

    def disconnected(session)
    end

    def helo(session, name)
    end

    # Verify +username+/+password+, raising +AuthenticationFailed+ otherwise.
    # +authorization_id+ is the SASL PLAIN authzid — an unverified claim, ignored here.
    def authenticate(session, username:, password:, authorization_id: "")
      raise AuthenticationFailed
    end

    # SASL mechanism names advertised on EHLO and accepted by +AUTH+. Advertising a
    # name before its handler exists is safe — one the engine cannot run replies 504.
    def auth_mechanisms(_session)
      %w[ PLAIN LOGIN ]
    end

    def mail_from(session, address)
    end

    def rcpt_to(session, address)
    end

    def receiving_started(session)
    end

    def headers_received(session)
    end

    # +io+ is a +DataReader+ of dot-unstuffed message bytes (contract in the README).
    # A SIZE or line-length failure raises from +read+ — a short body is not success.
    def receive(session, io)
    end

    def unknown_command(_session, _line)
      raise CommandNotRecognized
    end

    # Override to supply a Session subclass.
    def build_session
      Session.new
    end

    # Override for per-command policy (rate limits, session expiry, …). Call
    # +super+ to keep the engine's command dispatch.
    def process_line(session, line)
      case session.phase
      when :auth_plain
          accept_plain_credential(session, line)
      when :auth_login_user
          accept_login_username(session, line)
      when :auth_login_pass
          accept_login_password(session, line)
      else
          process_command_line(session, line)
      end
    end

    def shutdown?
      @shutdown
    end

    private
      # Order matters: it decides which error a caller sees when two options are
      # wrong at once.
      def validate_options(tls:, auth:, starttls:, max_connections:, max_processings:,
        max_connections_per_ip:, max_recipients:, max_auth_failures:, max_exceptions:,
        min_data_rate:, error_sleep_after:, error_sleep_time:, stress_threshold:, max_messages_per_ip:, max_tls_sessions_per_ip:,
        max_auth_attempts_per_ip:, eight_bit_mime:, smtputf8:, logger:, logger_severity:)
        raise ArgumentError, "Unknown auth mode #{auth.inspect}" unless AUTH_POLICIES.include?(auth)
        raise ArgumentError, "Unknown starttls mode #{starttls.inspect}" unless STARTTLS_POLICIES.include?(starttls)
        raise ArgumentError, "max_recipients must be at least 100 (RFC 5321 §4.5.3.1)" if max_recipients < 100
        raise ArgumentError, "starttls: :required requires a tls object" if starttls == :required && tls.nil?
        # RFC 6531 §3.1: a server offering SMTPUTF8 MUST also announce 8BITMIME —
        # internationalized mail is 8-bit, so BODY=8BITMIME would earn a 501 otherwise.
        raise ArgumentError, "smtputf8: true requires eight_bit_mime: true (RFC 6531 §3.1)" if smtputf8 && !eight_bit_mime
        raise ArgumentError, "max_connections must be an Integer >= 1" unless max_connections.is_a?(Integer) && max_connections >= 1
        raise ArgumentError, "max_processings must be an Integer >= 1" unless max_processings.is_a?(Integer) && max_processings >= 1
        unless max_connections_per_ip.nil? || (max_connections_per_ip.is_a?(Integer) && max_connections_per_ip >= 1)
          raise ArgumentError, "max_connections_per_ip must be nil or an Integer >= 1"
        end
        unless max_auth_failures.nil? || (max_auth_failures.is_a?(Integer) && max_auth_failures >= 1)
          raise ArgumentError, "max_auth_failures must be nil or an Integer >= 1"
        end
        unless max_exceptions.nil? || (max_exceptions.is_a?(Integer) && max_exceptions >= 1)
          raise ArgumentError, "max_exceptions must be nil or an Integer >= 1"
        end
        unless min_data_rate.nil? || (min_data_rate.is_a?(Integer) && min_data_rate >= 1)
          raise ArgumentError, "min_data_rate must be nil or an Integer >= 1"
        end
        unless error_sleep_after.nil? || (error_sleep_after.is_a?(Integer) && error_sleep_after >= 1)
          raise ArgumentError, "error_sleep_after must be nil or an Integer >= 1"
        end
        unless error_sleep_time.is_a?(Numeric) && error_sleep_time >= 0
          raise ArgumentError, "error_sleep_time must be a Numeric >= 0"
        end
        unless stress_threshold.nil? || (stress_threshold.is_a?(Float) && stress_threshold > 0 && stress_threshold <= 1)
          raise ArgumentError, "stress_threshold must be nil or a Float above 0 and at most 1"
        end
        unless max_messages_per_ip.nil? || (max_messages_per_ip.is_a?(Integer) && max_messages_per_ip >= 1)
          raise ArgumentError, "max_messages_per_ip must be nil or an Integer >= 1"
        end
        unless max_tls_sessions_per_ip.nil? || (max_tls_sessions_per_ip.is_a?(Integer) && max_tls_sessions_per_ip >= 1)
          raise ArgumentError, "max_tls_sessions_per_ip must be nil or an Integer >= 1"
        end
        unless max_auth_attempts_per_ip.nil? || (max_auth_attempts_per_ip.is_a?(Integer) && max_auth_attempts_per_ip >= 1)
          raise ArgumentError, "max_auth_attempts_per_ip must be nil or an Integer >= 1"
        end
        # A supplied logger arrives with a level already set, and honoring a severity
        # here would mean reaching into an object we don't own — quietly relevelling a
        # Rails.logger for the whole process. So the two are exclusive rather than one
        # of them silently losing.
        if logger && logger_severity
          raise ArgumentError, "logger_severity cannot be combined with logger (set the level on the logger itself)"
        end
      end

      def build_default_logger(severity)
        Logger.new($stdout).tap do |logger|
          logger.level = severity
          logger.datetime_format = "%Y-%m-%dT%H:%M:%S.%L"
          logger.formatter = proc { |sev, datetime, _progname, msg| "#{datetime}: [#{sev}] #{msg.to_s.chomp}\n" }
        end
      end

      # Pre-bound +listeners+ are the alternative to host/port: the caller binds (port 0
      # included) and these addresses then say where the sockets actually landed.
      def listen_addresses_in(hosts, ports)
        if @listeners.any?
          raise ArgumentError, "listeners cannot be combined with host and port" if [ hosts, ports ].compact.any?

          @listeners.map { |listener| bound_address_in(listener) }
        else
          expand_addresses(hosts, ports).tap do |configured|
            raise ArgumentError, "host and port (or hosts and ports) are required" if configured.empty?
          end
        end
      end

      def expand_addresses(hosts, ports)
        host_list = Array(hosts).flat_map { |value| value.to_s.split(/[,\s]+/) }.map(&:strip).reject(&:empty?)
        port_list = Array(ports).flat_map { |value| value.to_s.split(/[,\s:]+/) }.map(&:strip).reject(&:empty?).map { |port| listen_port_in(port) }
        host_list.product(port_list)
      end

      # Base 10 explicitly: a zero-padded ENV "02525" would read as octal and quietly
      # bind 1365. The range is checked here so an impossible port names itself.
      def listen_port_in(port)
        number = Integer(port, 10)
        raise ArgumentError, "port must be between 1 and 65535, got #{port.inspect}" unless number.between?(1, 65_535)

        number
      end

      # A listener answers for itself: the socket it is already bound to is the address,
      # never what the caller meant to ask for.
      def bound_address_in(listener)
        unless %i[ accept addr closed? ].all? { |method| listener.respond_to?(method) } && !listener.closed?
          raise ArgumentError, "listeners must be open, bound TCP servers"
        end

        family, port, _name, ip = listener.addr(:numeric)
        raise ArgumentError, "listeners must be bound to a TCP address, got #{family.inspect}" unless family.to_s.start_with?("AF_INET")

        [ ip, port ]
      end

      # Supplied listeners are handed over for good: +stop+ closes them like any other,
      # so a restart takes freshly bound ones.
      def claimed_listeners
        raise "Listeners were closed by an earlier stop" if @listeners.any?(&:closed?)

        @listeners
      end

      # Reporting is off because a stop raised into a thread that has not reached its
      # loop yet unwinds through no rescue of ours — errors are logged from the loop.
      def attach_acceptors
        @acceptor_threads = @tcp_servers.map do |tcp_server|
          Thread.new { accept_loop(tcp_server) }.tap { |thread| thread.report_on_exception = false }
        end
      end

      def proxy_enabled?
        @proxy_hosts.any?
      end

      def proxy_allowed?(remote_ip)
        proxy_enabled? && !remote_ip.nil? && @proxy_hosts.any? { |allowed| allowed.include?(remote_ip) }
      end

      # A failed accept is usually the machine's problem, not ours — wait it out and
      # keep listening, because a listener that gives up leaves the process alive and
      # healthy-looking with nothing answering the port.
      def accept_loop(tcp_server)
        backoff = nil

        until shutdown?
          begin
            client = tcp_server.accept
            backoff = nil
            admit_connection(client)
          rescue StopService
            raise
          rescue *ACCEPT_RETRY_ERRORS
            backoff = nil
          rescue *ACCEPT_BACKOFF_ERRORS => e
            backoff = backoff ? [ backoff * 2, MAX_ACCEPT_BACKOFF ].min : MIN_ACCEPT_BACKOFF
            log(nil, Logger::ERROR, "Can't accept a connection, retrying in #{backoff}s: #{loggable_error(e)}")
            sleep backoff
          rescue StandardError
            # +stop+ settles the listeners, so +accept+ can fail on the way down.
            # Anything else is the listener itself, which retrying would only spin on.
            raise unless shutdown?
          end
        end
      rescue StopService
        # signaled by #stop, not an error
      rescue StandardError => e
        log(nil, Logger::FATAL, loggable_error(e), err: e)
      ensure
        close_tcp_server(tcp_server)
        @acceptor_threads.delete(Thread.current)
      end

      # An OS thread is the most expensive thing this process spends, and spending one
      # only to refuse the connection is what turns a connection flood into a thread
      # flood. Capacity is answered here, before the thread exists.
      def admit_connection(client)
        if claim_admission
          start_connection_thread(client)
        else
          refuse_connection(client)
        end
      end

      # Counted separately from +@connection_threads+, which a connection only joins
      # once its thread is running: under a flood that window is exactly when the
      # acceptor is deciding, and a count that lags there admits everything it
      # means to refuse.
      def claim_admission
        @slot_mutex.synchronize do
          if @admitted >= max_connections
            false
          else
            @admitted += 1
            true
          end
        end
      end

      def release_admission
        @slot_mutex.synchronize { @admitted -= 1 }
      end

      def start_connection_thread(client)
        Thread.new(client) do |io|
          handle_connection(io)
        ensure
          release_admission
        end
      rescue StandardError
        # The thread never started, so nothing else will hand the admission back.
        release_admission
        close_socket(client)
        raise
      end

      # Refusal is written from the acceptor, so it must never block: a client that
      # sends nothing and reads nothing would otherwise stall every connection behind
      # it. One 421 fits any socket buffer; a peer that cannot take it gets the close.
      def refuse_connection(client)
        log(nil, Logger::WARN, "Refused a connection past max_connections (#{max_connections})")
        client.write_nonblock("#{ServiceUnavailable.new.response}\r\n", exception: false)
      rescue StandardError
        # The peer is already gone, and the close below is all that is left to do.
      ensure
        close_socket(client)
      end

      def close_socket(socket)
        socket.close unless socket.closed?
      rescue StandardError
        # already gone
      end

      # Give in-flight connections a bounded moment to finish on their own, then force
      # stragglers and wait for them to unwind, so we never exit mid-message.
      def drain_connections(grace_seconds)
        deadline = monotonic_time + grace_seconds
        sleep 0.05 while connections? && monotonic_time < deadline

        stragglers = @connection_threads.dup
        stragglers.each { |thread| thread.raise(StopConnection) }
        unwind_stragglers(stragglers, [ grace_seconds, MIN_UNWIND_GRACE ].max)
      end

      # Exactly one StopConnection per straggler — waiting on one that swallows it would
      # hold the whole shutdown open. Then reset its socket and abandon the thread.
      def unwind_stragglers(stragglers, unwind_seconds)
        deadline = monotonic_time + unwind_seconds

        stragglers.each do |thread|
          unless joined?(thread, [ deadline - monotonic_time, 0 ].max)
            log(nil, Logger::ERROR, "Abandoning a connection that outlived the forced stop")
            abort_socket(thread[:mailsmtp_socket])
          end
        end
      end

      # A thread that died on its own exception re-raises it out of +join+ — including
      # the StopConnection we raised into it, which is an Exception and so reaches here
      # even when it went uncaught. It is finished either way, and neither a failure
      # nor a stop taken correctly may abandon the drain of the rest.
      def joined?(thread, timeout)
        !thread.join(timeout).nil?
      rescue Exception
        true
      end

      def close_listeners
        @tcp_servers.each { |tcp_server| close_tcp_server(tcp_server) }
        @acceptor_threads.clear
      end

      def close_tcp_server(tcp_server)
        tcp_server.close
      rescue StandardError
        # already gone
      end

      # Keyed by thread so a slot is released exactly where the connection is: a
      # count that drifted upward would leave the listener refusing everyone.
      def handle_connection(io)
        # Kept where the drain can reach it: a thread that never answers its
        # forced stop is abandoned, and the socket still has to be reset.
        Thread.current[:mailsmtp_socket] = io

        begin
          session = build_session
          io = run_session(session, io)
        rescue StopConnection
          # Forced stop after the grace window — RST so the peer does not sit
          # half-open waiting on a bare FIN.
          abort_socket(io)
          io = nil
        rescue StandardError => e
          log(nil, Logger::FATAL, loggable_error(e), err: e)
        ensure
          # The forced stop is held off until the slot is back: interrupting the release
          # would leave this dead thread counted against the caps forever.
          begin
            Thread.handle_interrupt(StopConnection => :never) do
              if io
                abort_socket(io) if shutdown?
                io.close unless io.closed?
              end

              release_connection_slot
            end
          rescue StopConnection, StandardError
            # Already gone — and a stop held off until the block boundary arrives with
            # the thread finished anyway, so there is nothing left for it to interrupt.
          end
        end
      end

      # Registers this thread under +remote_ip+ and enforces the per-IP cap, which only
      # becomes enforceable here: behind PROXY the peer's real address is not known until
      # its line is read. +enforce_per_ip: false+ spares an allowlisted PROXY peer's
      # shared IP. The global cap is answered in the acceptor and re-checked here as a
      # backstop for anything that reaches a connection without going through admission.
      def claim_connection_slot(remote_ip, enforce_per_ip: true)
        @slot_mutex.synchronize do
          if @connection_threads.include?(Thread.current)
            # The re-check runs even when the address is unchanged: a PROXY line naming
            # the peer's own IP would otherwise leave this connection exempt for life.
            raise_if_ip_cap_reached(remote_ip) if enforce_per_ip
            @connection_ips[Thread.current] = remote_ip
          else
            if max_connections && @connection_threads.size >= max_connections
              raise ServiceUnavailable, "Dropping connection: max_connections (#{max_connections}) reached"
            end
            raise_if_ip_cap_reached(remote_ip) if enforce_per_ip

            @connection_threads << Thread.current
            @connection_ips[Thread.current] = remote_ip
          end
        end
      end

      # Our own entry never counts against us: a re-claim is one connection
      # being reattributed, not a second one arriving.
      def raise_if_ip_cap_reached(remote_ip)
        if max_connections_per_ip && remote_ip
          taken = @connection_ips.count { |thread, ip| ip == remote_ip && thread != Thread.current }
          raise ServiceUnavailable, "Too many connections from #{remote_ip}" if taken >= max_connections_per_ip
        end
      end

      def release_connection_slot
        @slot_mutex.synchronize do
          @connection_threads.delete(Thread.current)
          @connection_ips.delete(Thread.current)
          # Safety: a mid-DATA abort must not leave a processing slot stuck.
          @processing_threads.delete(Thread.current)
          @slot_released.signal
        end
      end

      def claim_processing_slot
        @slot_mutex.synchronize do
          deadline = monotonic_time + @max_processings_wait
          until processings_count < max_processings
            remaining = deadline - monotonic_time
            raise ServiceUnavailable, "Dropping connection: no processing slot free within #{@max_processings_wait}s" if remaining <= 0

            @slot_released.wait(@slot_mutex, remaining)
          end
          @processing_threads << Thread.current
        end
      end

      def release_processing_slot
        @slot_mutex.synchronize do
          @processing_threads.delete(Thread.current)
          @slot_released.signal
        end
      end

      # A socket the client has already abandoned has no peer to name; claim under
      # a nil IP (counts only against the global cap).
      def run_session(session, io)
        notified_connected = false
        begin
          session.local_ip = io.addr(:numeric)[3]
          session.remote_ip = io.peeraddr(:numeric)[3]
          session.connected_at = Time.now.utc
          session.banner = "#{session.local_ip} ESMTP"
          session.greeting = session.local_ip

          claim_connection_slot(session.remote_ip, enforce_per_ip: !proxy_allowed?(session.remote_ip))
          connected(session)
          notified_connected = true

          # Greeting is before EHLO advertises ENHANCEDSTATUSCODES — plain 220.
          respond(io, session, reply(220, session.banner.to_s.strip, enhanced: nil))

          buffer = LineBuffer.new(pending_limit: @pending_input_limit,
            compaction_floor: READ_CHUNK_BYTES)
          idle_since = monotonic_time
          session_deadline = @max_session_duration && (idle_since + @max_session_duration)

          loop do
            if session.phase == :starttls
              begin
                io = upgrade_to_tls(io, buffer)
              rescue Timeout::Error, IO::TimeoutError
                raise ServiceUnavailable, "STARTTLS timed out"
              rescue StandardError => e
                log(session, Logger::ERROR, loggable_error(e), err: e)
                return io
              end

              # RFC 3207 §4.2: after the handshake, discard everything the client
              # told us in plaintext (HELO, envelope, AUTH) and require a fresh HELO.
              session.reset
              session.reset_authentication
              session.helo = nil
              session.encrypted_at = Time.now.utc
              record_tls_details(session, io)
              session.phase = :helo
              idle_since = monotonic_time
            end

            fill_buffer(io, buffer) do
              raise_if_session_expired(session_deadline)
              raise_if_idle_timeout(idle_since)
            end

            while (line = buffer.take_command)
              command_ok = false

              begin
                raise_if_session_expired(session_deadline)
                raise_if_idle_timeout(idle_since)
                raise PipeliningNotSupported if buffer.pending_line? && !pipelining_allowed?(session)

                max_line = auth_line_length?(session, line) ? MAX_AUTH_LINE_LENGTH : MAX_COMMAND_LINE_LENGTH
                raise InvalidParameters, "Command line too long" if line.bytesize + 2 > max_line
                log(session, Logger::DEBUG, "<<< #{loggable_command(session, line)}\n")

                output = process_line(session, line)

                # After 354, pull the body with a live reader into +receive+, then
                # one final reply — no SMTP responses mid-DATA.
                if session.phase == :data
                  respond(io, session, output) if output && !output.empty?
                  output = transfer_data(session, io, buffer, session_deadline: session_deadline)
                end

                respond(io, session, output) if output && !output.empty?
                command_ok = true
                break if session.close_after_reply
              rescue ServiceUnavailable
                # 421 aborts the connection: re-raise past the command loop so the
                # outer handler sends a single closing reply and drops the socket.
                raise
              rescue PipeliningNotSupported => e
                session.exceptions += 1
                log(session, Logger::ERROR, loggable_error(e), err: e)
                sleep @error_sleep_time if error_sleep?(session)
                respond(io, session, e.response)
                # Drop the pipelined continuation still buffered (e.g. an AUTH credential)
                # so it isn't re-read, logged unredacted, and run out of sequence.
                buffer.discard_pending
                raise_if_exception_caps(session, e)
              rescue Error => e
                session.exceptions += 1
                session.auth_failures += 1 if e.is_a?(AuthenticationFailed)
                log(session, Logger::ERROR, loggable_error(e), err: e)
                sleep @error_sleep_time if error_sleep?(session)
                respond(io, session, e.response)
                raise_if_exception_caps(session, e)
              # A forced stop is not this command failing: a 451 and carrying on
              # would run every command already pipelined behind it.
              rescue StopConnection, StopService
                raise
              rescue StandardError => e
                session.exceptions += 1
                log(session, Logger::ERROR, loggable_error(e), err: e)
                sleep @error_sleep_time if error_sleep?(session)
                respond(io, session, LocalError.new.response)
                raise_if_exception_caps(session, e)
              end

              # Idle timer advances only on a fully successful command — errors and
              # probes must not keep a slowloris session alive forever by themselves.
              idle_since = monotonic_time if command_ok

              # STARTTLS and QUIT end the plaintext conversation, so anything pipelined
              # behind them must not run as part of the session that follows.
              break if %i[ starttls quit ].include?(session.phase)
            end

            break if session.phase == :quit || session.close_after_reply || io.closed? || shutdown?
          end

          respond(io, session, reply(221, "Service closing transmission channel")) unless session.close_after_reply
        rescue StopConnection, StopService
          raise
        # A hang-up is routine, not an error — skip the 421. Must precede the
        # ServiceUnavailable rescue, which ConnectionLost extends. ETIMEDOUT is a fault.
        rescue EOFError, ConnectionLost, Errno::ECONNRESET, Errno::EPIPE, Errno::ECONNABORTED => e
          log(session, Logger::DEBUG, "Client hung up (#{e.class})", err: e)
        rescue ServiceUnavailable => e
          session.exceptions += 1
          log(session, Logger::ERROR, loggable_error(e), err: e)
          begin
            respond(io, session, e.response, abort_reply: true)
          rescue ServiceUnavailable, StandardError => send_error
            log(session, Logger::DEBUG, "Closing 421 never reached the client (#{send_error.class})", err: send_error)
          end
        rescue StandardError => e
          session.exceptions += 1
          log(session, Logger::ERROR, loggable_error(e), err: e)
          begin
            respond(io, session, ServiceUnavailable.new.response, abort_reply: true)
          rescue ServiceUnavailable, StandardError => send_error
            log(session, Logger::DEBUG, "Closing 421 never reached the client (#{send_error.class})", err: send_error)
          end
        ensure
          disconnected(session) if notified_connected
        end

        io
      end

      # RFC 5321 §4.1.1.1 constrains a HELO name, but refusing junk rejects too much
      # mail — substitute 1:1 instead, so an unbalanced "(" cannot forge a Received.
      def neuter_helo(name)
        # SMTPUTF8 is read server-wide here, not off the envelope: HELO comes
        # before MAIL FROM.
        utf8 = name.dup.force_encoding(Encoding::UTF_8) if @smtputf8

        if utf8&.valid_encoding?
          utf8.gsub(HELO_UNSAFE_UTF8, "?")
        else
          name.gsub(HELO_UNSAFE, "?")
        end
      end

      # Header bodies are US-ASCII (RFC 5322 §2.2) unless SMTPUTF8 was negotiated (RFC
      # 6532). Re-checked, not trusted: +session.helo+ and +received_header+ are public.
      def ascii_only_helo(session, helo)
        utf8 = helo.dup.force_encoding(Encoding::UTF_8) if session.envelope.smtputf8

        if utf8&.valid_encoding?
          utf8.gsub(HELO_UNSAFE_UTF8, "?")
        else
          helo.b.gsub(HELO_UNSAFE, "?")
        end
      end

      # Mask credentials before the DEBUG log: an AUTH value-state line is the secret
      # itself, and an inline "AUTH PLAIN/LOGIN <arg>" carries it in the argument.
      def loggable_command(session, line)
        if auth_value_phase?(session.phase)
          "[redacted credential]"
        elsif line.match?(/\AAUTH\s/i)
          line.sub(/\A(AUTH\s+\S+)\s+\S.*\z/i, '\1 [redacted]')
        else
          # Every command runs through here whether or not DEBUG is enabled, so
          # traffic carrying no credential skips the rewrite entirely.
          line
        end
      end

      def auth_value_phase?(phase)
        %i[ auth_plain auth_login_user auth_login_pass ].include?(phase)
      end

      # A bare exception's message *is* its class name, so the usual "message (Class)"
      # form would print it twice. The remote IP is left to +log+.
      def loggable_error(error)
        message = error.message.to_s
        message == error.class.name ? message : "#{message} (#{error.class})"
      end

      def respond(io, session, output, abort_reply: false)
        log(session, Logger::DEBUG, ">>> #{output}")

        unless io.closed?
          write_timeout = if abort_reply
            [ @write_timeout, ABORT_REPLY_WRITE_TIMEOUT ].compact.min
          else
            @write_timeout
          end

          if write_timeout
            Timeout.timeout(write_timeout) { io.print("#{output}\r\n") }
          else
            io.print("#{output}\r\n")
          end
        end
      rescue Timeout::Error, IO::TimeoutError
        raise ServiceUnavailable, "Write timed out"
      rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ECONNABORTED
        # The peer went away mid-reply. Nothing further can be delivered, so do
        # not let this surface as a server-side error and provoke a second write.
        raise ConnectionLost, "Connection lost while writing"
      end

      # Success and informational replies. Pass +enhanced: nil+ for replies that
      # omit the RFC 2034 status (greeting, EHLO multilines, 354, AUTH 334).
      def reply(code, text, enhanced: "2.0.0")
        if enhanced.nil?
          "#{code} #{text}"
        else
          "#{code} #{enhanced} #{text}"
        end
      end

      def process_command_line(session, line)
        # An allowlisted peer skips the per-IP cap until PROXY names the real client,
        # so require PROXY first (v1: a receiver must not guess) — not an open exemption.
        if proxy_allowed?(session.remote_ip) && !session.proxy && !line.match?(/\APROXY(\s+)/i)
          raise ServiceUnavailable, "Dropping connection: #{session.remote_ip} must send PROXY first"
        end

        case line
        when /\A(HELO|EHLO)(\s+.*)?\z/i
            process_helo(session, line)
        when /\APROXY(\s+)/i
            process_proxy(session, line)
        when /\ASTARTTLS\s*\z/i
            process_starttls(session)
        # The initial response is framed loosely and validated where it is decoded —
        # a second copy of the base64 alphabet here would only drift.
        when /\AAUTH(\s+)(\S+)(\s+\S+)?\s*\z/i
            process_auth(session, line)
        when /\ANOOP(\s+.*)?\z/i
            reply(250, "OK")
        when /\AVRFY(\s+.*)?\z/i
            # RFC 5321 §3.5 / §4.5.1: always implement VRFY; 252 is the safe
            # answer when we will not confirm mailbox existence.
            reply(252, "Cannot VRFY user, but will accept message and attempt delivery", enhanced: "2.5.0")
        when /\AEXPN(\s+.*)?\z/i
            raise CommandNotImplemented
        when /\AHELP(\s+.*)?\z/i
            raise CommandNotImplemented
        when /\ARSET\s*\z/i
            process_rset(session)
        when /\AQUIT\s*\z/i
            session.phase = :quit
            ""
        when /\AMAIL FROM:/i
            process_mail_from(session, line)
        when /\ARCPT TO:/i
            process_rcpt_to(session, line)
        when /\ADATA\s*\z/i
            process_data_start(session)
        when /\A(GET|POST|CONNECT)(\s+.*)?\z/i
            process_cross_protocol_request(session)
        else
            unknown_command(session, line)
        end
      end

      def process_helo(session, line)
        # Mid-AUTH / mid-DATA are not a fresh greeting opportunity.
        raise BadSequence if auth_value_phase?(session.phase) || session.phase == :data

        # Bare HELO/EHLO (no argument) must not treat the verb as the hostname.
        match = line.match(/\A(HELO|EHLO)(?:\s+(.*))?\z/i)
        name = match[2].to_s.strip
        raise InvalidParameters if name.empty?
        name = neuter_helo(name)

        # RFC 5321 §4.1.4: a later EHLO/HELO resets state exactly as RSET.
        session.reset if session.phase != :helo

        helo(session, name)
        session.helo = name
        session.phase = :ready

        if line.match?(/\AEHLO/i)
          [
            "250-#{session.greeting.to_s.strip}",
            "250-ENHANCEDSTATUSCODES",
            (max_message_size ? "250-SIZE #{max_message_size}" : nil),
            (@eight_bit_mime ? "250-8BITMIME" : nil),
            (@smtputf8 ? "250-SMTPUTF8" : nil),
            (@pipelining ? "250-PIPELINING" : nil),
            (auth_ehlo_line(session)),
            (starttls_available?(session) ? "250-STARTTLS" : nil),
            reply(250, "OK", enhanced: nil)
          ].compact.join("\r\n")
        else
          # RFC 2034: every reply carries an enhanced status except the greeting and
          # the answer to HELO/EHLO, where an RFC 821 client reads the server domain.
          reply(250, session.greeting.to_s.strip, enhanced: nil)
        end
      end

      def process_proxy(session, line)
        raise CommandNotRecognized unless proxy_enabled?
        raise BadSequence if session.phase != :helo
        raise ServiceUnavailable, "Dropping connection: PROXY not accepted from #{session.remote_ip}" unless proxy_allowed?(session.remote_ip)
        raise ServiceUnavailable, "Dropping connection: a second PROXY header on one connection" if session.proxy

        proxy_data = proxy_header_in(line)
        proxy_data = proxy(session, proxy_data) || proxy_data
        session.proxy = proxy_data
        # PROXY UNKNOWN (typically a health check) names no client, so apply the per-IP
        # cap to the peer we do have rather than leave the exemption standing.
        if proxy_data[:source_ip]
          claim_connection_slot(proxy_data[:source_ip], enforce_per_ip: true)
          session.remote_ip = proxy_data[:source_ip]
        else
          claim_connection_slot(session.remote_ip, enforce_per_ip: true)
        end

        # No SMTP reply — PROXY is a preamble, not a command the client awaits.
        ""
      end

      # PROXY v1 is a header of whitespace-separated fields, so read it as fields:
      # a transport, then either nothing more to say or the four endpoint values.
      # Anything the fields do not account for is a header we refuse to guess at.
      def proxy_header_in(line)
        fields = line.sub(/\APROXY\s+/i, "").split(/\s+/).reject(&:empty?)
        transport = fields.shift.to_s.upcase

        if transport == PROXY_UNSPECIFIED
          # v1 §2.1: the sender is declaring no connection, and the rest of the
          # header — a health checker's padding, usually — is ours to ignore.
          { proto: transport, source_ip: nil, source_port: nil, dest_ip: nil, dest_port: nil }
        elsif PROXY_TRANSPORTS.key?(transport) && fields.length == PROXY_ENDPOINT_FIELDS
          proxy_endpoints_in(transport, fields)
        else
          raise ServiceUnavailable, "Dropping connection: malformed PROXY header"
        end
      end

      # The transport names the family, so a TCP4 header carrying an IPv6 literal is
      # refused rather than quietly believed.
      def proxy_endpoints_in(transport, fields)
        source_ip, dest_ip, source_port, dest_port = fields
        family = PROXY_TRANSPORTS.fetch(transport)

        {
          proto: transport,
          source_ip: proxy_address_in(source_ip, family),
          source_port: proxy_port_in(source_port),
          dest_ip: proxy_address_in(dest_ip, family),
          dest_port: proxy_port_in(dest_port)
        }
      rescue UnusableProxyEndpoint
        raise ServiceUnavailable, "Dropping connection: unusable PROXY address or port"
      end

      def proxy_address_in(field, family)
        raise UnusableProxyEndpoint unless field.match?(PROXY_ADDRESS)

        address = IPAddr.new(field)
        raise UnusableProxyEndpoint unless address.public_send(family)

        address.to_s
      rescue IPAddr::Error
        raise UnusableProxyEndpoint
      end

      # Digits, then range. Base 10 for the same reason listen ports are: a proxy
      # that pads "08" must not be refused, and "010" must not arrive as port 8.
      # Integer() alone would also take "+80" and "8_0", which no proxy sends.
      def proxy_port_in(field)
        raise UnusableProxyEndpoint unless field.match?(PROXY_PORT)

        port = Integer(field, 10)
        raise UnusableProxyEndpoint unless port.between?(1, 65_535)

        port
      end

      def process_starttls(session)
        raise CommandNotRecognized unless tls
        raise BadSequence unless session.phase == :ready
        raise BadSequence if session.encrypted?
        raise TlsUnavailable if rate_limited?(session, @tls_session_rates, @max_tls_sessions_per_ip)

        session.phase = :starttls
        reply(220, "Ready to start TLS")
      end

      def process_auth(session, line)
        raise CommandNotRecognized if @auth == :disabled
        raise BadSequence if session.phase != :ready || session.authenticated?
        raise EncryptionRequired if encryption_required? && !session.encrypted?
        raise AuthenticationTemporarilyUnavailable if rate_limited?(session, @auth_attempt_rates, @max_auth_attempts_per_ip)

        auth_data = line.sub(/\AAUTH\s/i, "").strip.split(/\s+/)
        mechanism = auth_data[0].to_s.upcase
        raise AuthenticationTypeNotSupported unless auth_mechanism_offered?(session, mechanism)

        case mechanism
        when "PLAIN"
            if auth_data.length == 1
              session.phase = :auth_plain
              "334 "
            else
              accept_plain_credential(session, auth_data[1])
            end
        when "LOGIN"
            if auth_data.length == 1
              session.phase = :auth_login_user
              AUTH_LOGIN_USERNAME_PROMPT
            else
              accept_login_username(session, auth_data[1])
            end
        else
            raise AuthenticationTypeNotSupported
        end
      end

      def process_rset(session)
        raise BadSequence if auth_value_phase?(session.phase) || session.phase == :data
        raise EncryptionRequired if session.phase != :helo && encryption_required? && !session.encrypted?

        # Before HELO there is no transaction to clear; still answer 250 (RFC 5321).
        session.reset unless session.phase == :helo
        reply(250, "OK")
      end

      def process_mail_from(session, line)
        raise BadSequence if session.phase != :ready
        raise EncryptionRequired if encryption_required? && !session.encrypted?
        raise AuthenticationRequired if @auth == :required && !session.authenticated?
        raise RateLimited if rate_limited?(session, @message_rates, @max_messages_per_ip)

        data = line.sub(/\AMAIL FROM:/i, "").strip
        raise InvalidParameters if data.include?("\0")

        path, parameters = @path_parser.split_from_parameters(data)
        extensions = @parameter_parser.mail_from_extensions_in(parameters)
        address = @path_parser.address_in(path)

        begin
          apply_mail_from_extensions(session, extensions)
          address = mail_from(session, address) || address
        rescue StandardError
          # A refused MAIL FROM opens no transaction and leaves none of itself behind:
          # no inherited SIZE=, no AUTH= identity asserted for a message we rejected.
          session.reset
          raise
        end

        session.envelope.from = address
        session.phase = :mail
        reply(250, "OK")
      end

      # Every parameter lands at once, once the whole command has been accepted; absent
      # ones are assigned nil so the envelope carries this MAIL FROM and nothing else.
      def apply_mail_from_extensions(session, extensions)
        session.envelope.declared_size = extensions[:declared_size]
        session.envelope.body_encoding = extensions[:body_encoding]
        session.envelope.smtputf8 = extensions[:smtputf8]
        session.envelope.auth_identity = extensions[:auth_identity]
      end

      def process_rcpt_to(session, line)
        raise BadSequence unless %i[ mail rcpt ].include?(session.phase)
        raise EncryptionRequired if encryption_required? && !session.encrypted?
        raise AuthenticationRequired if @auth == :required && !session.authenticated?
        raise TooManyRecipients if session.envelope.to.size >= max_recipients

        data = line.sub(/\ARCPT TO:/i, "").strip
        raise InvalidParameters if data.include?("\0")
        raise InvalidParameters if !@smtputf8 && !data.ascii_only?

        # The forward-path ends at its ">" for the same reason the reverse-path does.
        # RCPT TO advertises no parameters: 555 if the tail parses as one, else 501.
        path, unhandled = @path_parser.split_from_parameters(data)
        @parameter_parser.raise_if_unhandled(unhandled)

        address = @path_parser.address_in(path)
        # Only the reverse-path may be null (RFC 5321 §4.1.1.3).
        raise InvalidParameters, "Empty recipient address" if address.empty?

        address = rcpt_to(session, address) || address
        session.envelope.to << address
        session.phase = :rcpt
        reply(250, "OK")
      end

      def process_data_start(session)
        raise BadSequence if session.phase != :rcpt
        raise EncryptionRequired if encryption_required? && !session.encrypted?
        raise AuthenticationRequired if @auth == :required && !session.authenticated?

        # Claimed before the 354: a saturated server must not invite a body it
        # cannot process yet and only find that out afterward.
        claim_processing_slot
        session.phase = :data
        reply(354, "Start mail input; end with <CRLF>.<CRLF>", enhanced: nil)
      end

      # An HTTP verb on the SMTP port is a cross-protocol attack (ALPACA). None is an
      # SMTP verb, so there is no legitimate traffic to lose: answer once and hang up.
      def process_cross_protocol_request(session)
        session.close_after_reply = true
        reply(502, "Command not implemented", enhanced: "5.5.1")
      end

      # Send no SMTP replies until the terminating "." — then one success or error.
      # The reply is assembled with the processing slot already handed back.
      def transfer_data(session, io, buffer, session_deadline: nil)
        error = receive_data(session, io, buffer, session_deadline: session_deadline)

        if error
          session.exceptions += 1
          log(session, Logger::ERROR, loggable_error(error), err: error)
          sleep @error_sleep_time if error_sleep?(session)
          error.response
        else
          reply(250, "Requested mail action okay, completed")
        end
      end

      # Runs +receive+ over the body and drains to the terminating ".", returning the
      # error to reply with, or nil on success.
      def receive_data(session, io, buffer, session_deadline: nil)
        idle_since = [ monotonic_time ]
        data_started = idle_since[0]
        bytes_received = [ 0 ]
        reader = DataReader.new(
          max_message_size: max_message_size,
          max_line_length: MAX_TEXT_LINE_LENGTH,
          on_headers: -> { headers_received(session) }
        ) { read_data_line(io, buffer, idle_since, session_deadline, data_started, bytes_received) }

        reader = PrefixedReader.new(received_header(session), reader) if @add_received

        error = nil
        aborting = false
        begin
          receiving_started(session)
          receive(session, reader)
        rescue ConnectionLost
          # Nothing left to drain toward, and no reply to line up behind the body.
          aborting = true
          raise
        rescue ServiceUnavailable
          # The app is refusing with a 421 — keep draining to the terminating "."
          # so a sender still writing the body isn't hit with a write-side reset.
          raise
        rescue Error => e
          error = e
        # A forced stop landing in +receive+ is not an application bug, and the drain
        # must not go back to the network while the service is shutting down.
        rescue StopConnection, StopService
          aborting = true
          raise
        rescue StandardError => e
          log(session, Logger::ERROR, loggable_error(e), err: e)
          error = LocalError.new
        ensure
          # Draining resynchronizes to the terminating "." so the session can carry on;
          # it stops early on a failure there is nothing to resynchronize for, whether
          # +receive+ hit it or the drain itself did.
          reader.drain unless aborting
          session.reset
          # RFC 5321 §4.5.3.1.7: after 552 for SIZE, the server may close. Same for a
          # bare LF or CR, whose sender may never write the CRLF "." we would wait for,
          # and when drain hit the absolute ceiling with no "." in sight.
          if (error || reader.failure)&.unrecoverable? || reader.drain_ceiling_hit?
            session.close_after_reply = true
          end
        end

        error || reader.failure
      ensure
        release_processing_slot
      end

      # Next DATA line as dot-unstuffed bytes plus CRLF, or +nil+ at the terminator, which
      # counts only CRLF-terminated (RFC 5321 / CVE-2023-51764 smuggling): bare-LF is body.
      def read_data_line(io, buffer, idle_since, session_deadline, data_started, bytes_received)
        loop do
          raise_if_session_expired(session_deadline)
          raise_if_data_rate_too_low(data_started, bytes_received[0])

          body_line = buffer.take_body_line
          unless body_line
            fill_buffer(io, buffer) do
              raise_if_session_expired(session_deadline)
              raise_if_idle_timeout(idle_since[0])
              raise_if_data_rate_too_low(data_started, bytes_received[0])
            end

            raise ConnectionLost, "Connection lost during DATA" if io.closed?
            raise ServiceUnavailable, "Server shutting down" if shutdown?
            next
          end

          line, crlf = body_line
          raise BareNewline if @forbid_bare_newline && !crlf
          # RFC 5321 §2.3.8 allows CR only as part of CRLF — an interior one is the
          # ambiguity smuggling is built on. Checked before dot-unstuffing.
          raise BareCarriageReturn if @forbid_bare_newline && line.include?("\r")

          idle_since[0] = monotonic_time

          # End-of-data is only <CRLF>.<CRLF> — never a bare-LF dot.
          return nil if line == "." && crlf

          line.slice!(0) if line[0] == "."
          bytes_received[0] += line.bytesize + 2
          return "#{line}\r\n"
        end
      rescue LineBuffer::BufferOverrun
        raise ServiceUnavailable, "Input buffer overrun"
      rescue EOFError, Errno::ECONNRESET, Errno::EPIPE, Errno::ECONNABORTED
        raise ConnectionLost, "Connection lost during DATA"
      end

      # Every byte a session reads arrives through here: one read attempt into the
      # buffer, or one bounded park when the socket has nothing ready. Nothing is
      # read while the buffer already holds a whole line, so a pipelined command is
      # answered from what we have instead of waiting on the socket for it.
      #
      # Parking on the raw fd is safe because read_nonblock drained the SSL buffer;
      # renegotiation is why WaitWritable has to be answered as well. Timeouts are
      # the caller's: the guard block runs before each attempt to take more bytes.
      def fill_buffer(io, buffer)
        unless buffer.pending_line?
          yield
          buffer << io.read_nonblock(READ_CHUNK_BYTES)
        end
      rescue IO::WaitReadable
        yield
        IO.select([ io.to_io ], nil, nil, READ_WAIT_SECONDS)
      rescue IO::WaitWritable
        yield
        IO.select(nil, [ io.to_io ], nil, READ_WAIT_SECONDS)
      end

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # The session's socket only ever changes hands here, and nothing buffered may
      # survive the swap: bytes read in the clear could have been written by a MITM,
      # so reading them back inside the tunnel is CVE-2011-0411. Handing back the
      # tunnel is the same call that empties the buffer, so there is no way to take
      # one without the other.
      def upgrade_to_tls(io, buffer)
        with_handshake_timeout(io) { tls.start(io) }.tap do |tls_io|
          # Don't trust +tls+ to set this: forgetting it leaves the raw fd open
          # until GC, and a forced abort's SO_LINGER RST silently no-ops.
          tls_io.sync_close = true if tls_io.respond_to?(:sync_close=)
          buffer.discard_pending
        end
      end

      # Prefer the socket's own timeout, which interrupts OpenSSL's accept; Timeout is
      # the fallback for pure-Ruby +tls+ objects.
      def with_handshake_timeout(io)
        handshake_timeout = stressed? ? [ @handshake_timeout, STRESS_TIMEOUT ].min : @handshake_timeout
        previous = io.respond_to?(:timeout) ? io.timeout : :unset
        io.timeout = handshake_timeout if io.respond_to?(:timeout=)
        Timeout.timeout(handshake_timeout) { yield }
      ensure
        if previous != :unset && io.respond_to?(:timeout=)
          io.timeout = previous
        end
      end

      def raise_if_idle_timeout(idle_since)
        read_timeout = stressed? ? [ @read_timeout, STRESS_TIMEOUT ].compact.min : @read_timeout
        if read_timeout && monotonic_time - idle_since > read_timeout
          raise ServiceUnavailable, "Read timed out"
        end
      end

      # Without +read_timeout+ there is no grace for the first bytes to arrive in,
      # so the rate is not enforced either.
      def raise_if_data_rate_too_low(data_started, bytes_received)
        if @min_data_rate && @read_timeout &&
            monotonic_time > data_started + @read_timeout + bytes_received.fdiv(@min_data_rate)
          raise ServiceUnavailable, "Data rate too low"
        end
      end

      def raise_if_session_expired(session_deadline)
        if session_deadline && monotonic_time > session_deadline
          raise ServiceUnavailable, "Session time limit exceeded"
        end
      end

      def accept_plain_credential(session, encoded_auth_response)
        # limit: -1 keeps a trailing empty password instead of dropping it, which would
        # otherwise turn "\0user\0" into 2 fields and 501 it without an auth failure.
        auth_values = decode_base64(encoded_auth_response).split("\x00", -1)
        raise InvalidParameters unless auth_values.length == 3

        authorize(session, *auth_values)
      ensure
        session.phase = :ready
      end

      # LOGIN splits the credential over two base64 lines; hold the username
      # between turns, then run the same authorize path PLAIN does.
      def accept_login_username(session, encoded_username)
        session.auth_login_username = decode_base64(encoded_username)
        session.phase = :auth_login_pass
        AUTH_LOGIN_PASSWORD_PROMPT
      rescue Error
        session.phase = :ready
        raise
      end

      def accept_login_password(session, encoded_password)
        authorize(session, "", session.auth_login_username, decode_base64(encoded_password))
      ensure
        session.auth_login_username = nil
        session.phase = :ready
      end

      # Strictly, so a mangled credential is refused: Base64.decode64 silently discards
      # anything outside the alphabet, turning a smuggled byte into a plausible one.
      def decode_base64(encoded_auth_response)
        Base64.strict_decode64(encoded_auth_response)
      rescue ArgumentError
        raise InvalidParameters
      end

      # The SASL PLAIN authzid is a claim, not a fact (RFC 4954 §4). The application
      # grants it by returning that identity; any other return falls back to the login.
      def authorize(session, requested_authorization_id, authentication_id, authentication)
        # base64 can carry bytes the command grammar never allows through; CR/LF here
        # would forge header lines when an application logs who authenticated.
        if [ requested_authorization_id, authentication_id ].any? { |value| value.to_s.match?(/[\r\n]/) }
          raise InvalidParameters
        end

        granted = authenticate(session,
          username: authentication_id,
          password: authentication,
          authorization_id: requested_authorization_id)
        # A non-empty String or Symbol is the application naming the identity —
        # authoritative, and may differ from the client's claim.
        granted = granted.to_s if granted.is_a?(String) || granted.is_a?(Symbol)
        granted_explicitly = granted.is_a?(String) && !granted.empty?
        # The grant gets the same CR/LF check as the claim: an
        # application-assembled identity can carry it just as easily.
        raise LocalError if granted_explicitly && granted.match?(/[\r\n]/)

        authorization_id = granted_explicitly ? granted : authentication_id

        # Recorded even when the login is about to be refused, so an application
        # can audit who was impersonated.
        session.requested_authorization_id = requested_authorization_id

        # Refuse only a different identity the application didn't grant — asking to be
        # yourself is allowed (RFC 4616 §2). Compared as bytes: base64 gives BINARY.
        requested = requested_authorization_id.to_s
        if !requested.empty? && !granted_explicitly && requested.b != authentication_id.to_s.b
          raise AuthenticationFailed
        end

        session.authorization_id = authorization_id
        session.authentication_id = authentication_id
        session.authenticated_at = Time.now.utc
        reply(235, "OK", enhanced: "2.7.0")
      end

      def starttls_available?(session)
        tls && !session.encrypted?
      end

      # OpenSSL returns cipher as [name, version, bits, alg_bits]; keep the name.
      def record_tls_details(session, io)
        session.tls_version = io.ssl_version if io.respond_to?(:ssl_version)

        if io.respond_to?(:cipher)
          cipher = io.cipher
          session.tls_cipher = cipher.is_a?(Array) ? cipher[0] : cipher
        end
      end

      def auth_available?(session)
        @auth != :disabled &&
          (!encryption_required? || session.encrypted?) &&
          auth_mechanisms(session).any?
      end

      def auth_ehlo_line(session)
        if auth_available?(session)
          mechanisms = auth_mechanisms(session).map { |name| name.to_s.upcase }.uniq
          "250-AUTH #{mechanisms.join(" ")}" unless mechanisms.empty?
        end
      end

      def auth_mechanism_offered?(session, mechanism)
        auth_mechanisms(session).any? { |name| name.to_s.casecmp?(mechanism) }
      end

      def encryption_required?
        @starttls == :required
      end

      def auth_line_length?(session, line)
        auth_value_phase?(session.phase) || line.match?(/\AAUTH\s/i)
      end

      # After the SMTP error reply, drop the session when AUTH or general error
      # budgets are exhausted. +nil+ disables either ceiling.
      def raise_if_exception_caps(session, error)
        if error.is_a?(AuthenticationFailed) && @max_auth_failures &&
            session.auth_failures >= @max_auth_failures
          raise ServiceUnavailable, "Too many authentication failures"
        end
        max_exceptions = stressed? ? STRESS_MAX_EXCEPTIONS : @max_exceptions
        if max_exceptions && session.exceptions >= max_exceptions
          raise ServiceUnavailable, "Too many protocol errors"
        end
      end

      # Postfix's smtpd_soft_error_limit: past +error_sleep_after+ errors, every further
      # error reply waits +error_sleep_time+ first. Not under stress, whose one-error
      # budget has already ended the session by then.
      def error_sleep?(session)
        @error_sleep_after && !stressed? && session.exceptions > @error_sleep_after
      end

      # Counts the attempt, then answers whether it went over +limit+. Keyed on
      # +remote_ip+, which behind PROXY is the client the proxy named.
      def rate_limited?(session, rates, limit)
        return false unless limit

        rates.count(session.remote_ip) > limit
      end

      # SO_LINGER with timeout 0 yields RST on close — used on forced stop so
      # clients do not linger on a half-closed FIN.
      def abort_socket(io)
        if io && !io.closed?
          io.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack("ii"))
          io.close
        end
      rescue StandardError
        # already gone
      end

      # Body lines are not covered: +read_data_line+ takes them from the reader itself.
      # PROXY is exempt because real clients send HELO/EHLO straight behind the preamble.
      def pipelining_allowed?(session)
        @pipelining || (proxy_enabled? && session.phase == :helo)
      end
  end
end
