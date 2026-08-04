require_relative "test_helper"
require_relative "support/fuzz_dialog"

# Replays generated and checked-in dialogs against a live +MailSmtp::Server+ over a
# real socket, holding the parser to its invariants (seeds and corpus: README).
class MailSmtp::FuzzTest < MailSmtp::ServerIntegrationTest
  SEED = 1
  ITERATIONS = 24
  # A reply the server owes us and does not send is a hang; the client-side
  # ceiling is what turns it into a failure instead of a stalled suite.
  REPLY_TIMEOUT = 5
  # After these the session is over, so the replies still owed for a pipelined
  # write are never coming.
  CLOSING_CODES = [ 221, 421 ].freeze
  ENVELOPE_VERB = /\A(MAIL FROM:|RCPT TO:)/i
  # SASL PLAIN "\0user\0secret", the credential FuzzServer accepts.
  PLAIN_CREDENTIAL = "AHVzZXIAc2VjcmV0"

  Profile = Data.define(:name, :server, :port, :prologue, :pipelining, :smtputf8, :strict_path)

  # Records what the application was handed for every envelope command, so an
  # invariant can hold it against the bytes the client actually sent.
  class FuzzServer < MailSmtp::Server
    attr_reader :envelope_calls, :unexpected_errors

    def initialize(**)
      super
      @envelope_calls = []
      @unexpected_errors = []
    end

    def mail_from(session, address)
      @envelope_calls << { command: :mail_from, address: address, auth_identity: session.envelope.auth_identity }
      address
    end

    def rcpt_to(_session, address)
      @envelope_calls << { command: :rcpt_to, address: address, auth_identity: nil }
      address
    end

    def authenticate(_session, username:, password:, authorization_id: "")
      raise MailSmtp::AuthenticationFailed unless username == "user" && password == "secret"
      username
    end

    def receive(_session, io)
      io.read
    end

    # The engine answers 451 for anything it did not model and logs the exception here,
    # so this hook is the only place an unrescued error — the fuzzer's quarry — shows.
    def log(session, severity, msg, err: nil)
      @unexpected_errors << err if err && !err.is_a?(MailSmtp::Error)
      super
    end
  end

  def setup
    super
    @profiles = [ plain_profile, extended_profile, lenient_profile ]
  end

  def test_seed_corpus_holds_the_parser_invariants
    MailSmtp::FuzzCorpus.dialogs.each do |name, payloads|
      @profiles.each { |profile| replay(profile, payloads, label: "corpus #{name}") }
    end
  end

  def test_generated_dialogs_hold_the_parser_invariants
    seeds.each do |seed|
      @profiles.each do |profile|
        dialog = MailSmtp::FuzzDialog.new(seed, pipelining: profile.pipelining).payloads
        replay(profile, dialog, label: "seed #{seed}")
      end
    end
  end

  private
    def seeds
      first = Integer(ENV.fetch("MAILSMTP_FUZZ_SEED", SEED))
      count = Integer(ENV.fetch("MAILSMTP_FUZZ_ITERATIONS", ITERATIONS))
      (first...(first + count)).to_a
    end

    def plain_profile
      server, port = start_fuzz_server(auth: :disabled)
      Profile.new(name: "plain", server: server, port: port, prologue: [],
        pipelining: false, smtputf8: false, strict_path: true)
    end

    # Every extension on at once, and authenticated up front: with AUTH required the
    # engine refuses MAIL FROM before it ever parses the path, which is what we came for.
    def extended_profile
      server, port = start_fuzz_server(auth: :required, tls: FakeTls.new, smtputf8: true,
        eight_bit_mime: true, pipelining: true, add_received: true)
      Profile.new(name: "extended", server: server, port: port,
        prologue: [ "EHLO fuzz.example", "AUTH PLAIN #{PLAIN_CREDENTIAL}" ],
        pipelining: true, smtputf8: true, strict_path: true)
    end

    # The same dialogs against +strict_path: false+, where the address ends at the first
    # space instead of at a bracket. The invariants do not move with the boundary.
    def lenient_profile
      server, port = start_fuzz_server(auth: :disabled, strict_path: false)
      Profile.new(name: "lenient", server: server, port: port, prologue: [],
        pipelining: false, smtputf8: false, strict_path: false)
    end

    # Each profile listens on its own socket, so bind one here rather than share
    # the test's default listener between all three.
    def start_fuzz_server(**overrides)
      listener = bind_listener
      # No exception or auth-failure ceiling: a fuzz dialog is mostly protocol errors,
      # and dropping at twenty would end every run right where it gets interesting.
      options = server_options(listeners: [ listener ], max_message_size: 4096,
        max_exceptions: nil, max_auth_failures: nil, **overrides)
      [ start(FuzzServer.new(**options)), port_of(listener) ]
    end

    # One dialog on its own connection. Violations are collected rather than
    # raised so a failure reports the whole transcript, not the line it died on.
    def replay(profile, payloads, label:)
      transcript = []
      violations = []
      errors_before = profile.server.unexpected_errors.size

      socket = connect(profile.port)
      socket.binmode
      socket.timeout = REPLY_TIMEOUT

      begin
        read_reply(socket, transcript, violations)
        converse(profile, socket, profile.prologue + payloads, transcript, violations)
      rescue IO::TimeoutError
        violations << "No reply within #{REPLY_TIMEOUT}s — the server is hung"
      rescue Errno::ECONNRESET, Errno::EPIPE
        # A dropped connection is legitimate for a good few of these dialogs (421
        # aborts, cross-protocol probes), and the replies that arrived were checked.
      ensure
        close(socket)
      end

      profile.server.unexpected_errors[errors_before..].each do |error|
        violations << "Unrescued #{error.class}: #{error.message}"
      end

      assert violations.empty?, report(profile, label, transcript, violations)
    end

    def converse(profile, socket, payloads, transcript, violations)
      index = 0

      while index < payloads.size
        payload = payloads[index]
        index += 1
        segments = segments_in(payload)
        calls_before = profile.server.envelope_calls.size

        write(socket, payload, transcript)
        replies = collect_replies(socket, segments.size, transcript, violations)
        check_envelope(profile, segments, replies, profile.server.envelope_calls[calls_before..], violations)
        # A reply the server owes us and never sent leaves the rest of the dialog
        # unanchored, so the conversation ends here rather than blaming the next payload.
        break if replies.size < segments.size

        # 354 is the only invitation to send a body; a rejected DATA leaves
        # the following payloads to be read as the commands they look like.
        if segments.one? && replies.first[:code] == 354
          index = deliver_body(socket, payloads, index, transcript, violations)
        end
      end
    end

    # Body payloads until the client's own ".", then the single reply covering the
    # whole message. A dialog that runs out mid-body still gets a terminator.
    def deliver_body(socket, payloads, index, transcript, violations)
      terminated = false

      while index < payloads.size && !terminated
        payload = payloads[index]
        index += 1
        terminated = payload == "."
        write(socket, payload, transcript)
      end

      write(socket, ".", transcript) unless terminated
      collect_replies(socket, 1, transcript, violations)
      index
    end

    def write(socket, payload, transcript)
      bytes = wire_bytes(payload)
      transcript << ">>> #{bytes.inspect}"
      socket.write(bytes)
    end

    # A payload already ending in a newline brings its own terminator — that
    # is how a body line gets a bare LF — and otherwise gets a CRLF.
    def wire_bytes(payload)
      bytes = payload.b
      bytes.end_with?("\n") ? bytes : "#{bytes}\r\n"
    end

    # The commands one write frames. More than one only happens under
    # PIPELINING, where the engine answers each: segment count is reply count.
    def segments_in(payload)
      wire_bytes(payload).split("\n", -1)[..-2]
    end

    def collect_replies(socket, expected, transcript, violations)
      [].tap do |replies|
        expected.times do
          reply = read_reply(socket, transcript, violations)
          break unless reply

          replies << reply
          break if CLOSING_CODES.include?(reply[:code])
        end
      end
    end

    # One reply, following its continuation lines, or nil once the server has
    # closed the connection.
    def read_reply(socket, transcript, violations)
      lines = []
      loop do
        line = socket.gets
        break if line.nil?

        transcript << "<<< #{line.inspect}"
        lines << line
        break unless line[3] == "-"
      end
      unless lines.empty?
        lines.each { |line| check_reply_line(line, violations) }
        { code: lines.last[0, 3].to_i, lines: lines }
      end
    end

    def check_reply_line(line, violations)
      violations << "Reply is not CRLF terminated: #{line.inspect}" unless line.end_with?("\r\n")
      violations << "Reply has no valid 3-digit code: #{line.inspect}" unless line.match?(/\A[2-5]\d\d[ -]/)
    end

    # Line up each accepted envelope command with the address its hook was handed — but
    # only when every reply arrived, or which command the last one answers is ambiguous.
    def check_envelope(profile, segments, replies, calls, violations)
      return unless replies.size == segments.size

      pending = calls.dup
      segments.zip(replies).each do |segment, reply|
        command = segment.delete("\r\n")
        next unless command.match?(ENVELOPE_VERB) && (200..299).cover?(reply[:code])

        if (call = pending.shift)
          check_framing(profile, command, call, violations)
        else
          violations << "Accepted #{command.inspect} without handing the application an address"
        end
      end

      pending.each do |call|
        violations << "The application saw #{call[:address].inspect} for a command that was not accepted"
      end
    end

    # The engine may take off the framing — brackets, the whitespace inside them, an RFC
    # 5321 §3.6.1 source route — and nothing else, so what is left is a suffix of it.
    def check_framing(profile, command, call, violations)
      address = call[:address].b
      tail = command.sub(ENVELOPE_VERB, "").strip
      path = path_sent(profile, tail)

      if path.nil?
        violations << "Accepted a path the client never framed: #{tail.inspect}"
      elsif address.empty?
        # RFC 5321 §4.5.5: the null sender is a literal <> and nothing else, so a source
        # route stripped away to "" is forged — and so is an unbracketed path.
        violations << "Null sender forged from #{tail.inspect}" unless path == "<>"
        violations << "Empty recipient accepted from #{tail.inspect}" if call[:command] == :rcpt_to
      elsif !mailbox_sent(path).end_with?(address)
        violations << "Address #{address.inspect} is not what #{path.inspect} carried"
      end

      violations << "Address #{address.inspect} kept framing or control bytes" if address.match?(/[<>\r\n\0]/n)
      check_auth_identity(profile, call, violations)
    end

    # The path as the client framed it: bracketed always, and under a lenient server
    # also a bare run up to the first space, the only other shape it may accept.
    def path_sent(profile, tail)
      if profile.strict_path || tail.start_with?("<")
        tail[/\A<[^<>]*>/]
      else
        tail[/\A[^\s<>]+/]
      end
    end

    def mailbox_sent(path)
      path.start_with?("<") ? path[1..-2].strip : path
    end

    # AUTH= is decoded from xtext (RFC 4954 §5), which is how a byte the
    # command grammar rejects would reach whatever logs the claim.
    def check_auth_identity(profile, call, violations)
      identity = call[:auth_identity]

      unless identity.nil? || identity.empty?
        violations << "AUTH= identity #{identity.inspect} carries a control byte" if identity.b.match?(/[\x00-\x1f\x7f]/n)
        violations << "AUTH= identity #{identity.inspect} is not ASCII" if !profile.smtputf8 && !identity.ascii_only?
      end
    end

    def report(profile, label, transcript, violations)
      [
        "#{label}, profile #{profile.name}:",
        *violations.map { |violation| "  - #{violation}" },
        "",
        "Replay with: MAILSMTP_FUZZ_SEED=<seed> MAILSMTP_FUZZ_ITERATIONS=1 " \
          "bundle exec rake test TEST=test/fuzz_test.rb",
        "",
        "Transcript:",
        *transcript.map { |line| "  #{line}" }
      ].join("\n")
    end
end
