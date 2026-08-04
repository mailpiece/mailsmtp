module MailSmtp
  # Deterministic generator of adversarial SMTP dialogs, and reader for the seed corpus;
  # every choice comes from +Random.new(seed)+, so a failure replays from its seed alone.
  class FuzzDialog
    # RFC 5321 §4.5.3.1.3 puts a path at 256 octets including its brackets, so
    # this is the largest one that must still be accepted.
    LONGEST_PATH = "<#{"a" * (255 - "<@example.com>".bytesize)}@example.com>".freeze
    # A Gmail forwarding address: 66 octets of local part inside a path barely
    # 80 long — traffic the 64-octet local-part ceiling would wrongly refuse.
    GMAIL_FORWARDER = "<recipient.name+caf_=recipient.name=some.longest.domain.example.com@gmail.com>"

    GREETINGS = [
      "EHLO fuzz.example",
      "HELO fuzz.example",
      "EHLO",
      "EHLO ",
      "EHLO [127.0.0.1]",
      "EHLO fuzz(.example",
      "EHLO fuzz\";@ .example",
      "EHLO fuzzé.example",
      "EHLO fuzz\xFF.example",
      "EHLO #{"h" * 600}",
      "ehlo fuzz.example",
      "NOOP"
    ].freeze

    # Paths that have caused a bug here or sit next to one: source routes stripping to
    # nothing, nested brackets, parameter-shaped quoted local parts, the length edges.
    PATHS = [
      "<user@example.com>",
      "<>",
      "< >",
      "<  >",
      "<@relay1.example:>",
      "<@a,@b:>",
      "<@a,@b:user@example.com>",
      "<@relay1.example:user@example.com>",
      "<:user@example.com>",
      "<@:>",
      "<a<b@example.com>",
      "<a>b@example.com>",
      '<"a>b"@example.com>',
      '<"pay SIZE=1 me"@example.com>',
      '<"a b"@example.com>',
      "user@example.com",
      "<user@example.com",
      "user@example.com>",
      "<<user@example.com>>",
      "<user@example.com> <other@example.com>",
      "<Postmaster>",
      "<user@[127.0.0.1]>",
      "<user.@example.com>",
      "<user@example.com\x00>",
      "<user@example.com\r>",
      "<user@exämple.com>",
      "<user@ex\xFFample.com>",
      "<#{"a" * 300}@example.com>",
      LONGEST_PATH,
      GMAIL_FORWARDER,
      "<>>",
      "><",
      ""
    ].freeze

    # ESMTP parameters, including the xtext forms AUTH= is decoded from: a
    # complete escape, a truncated one, a bare "+", and a non-hex pair.
    PARAMETERS = [
      "",
      "",
      " SIZE=100",
      " SIZE=0100",
      " SIZE=99999999999",
      " SIZE=",
      " SIZE=1x",
      " SIZE=-1",
      " BODY=8BITMIME",
      " BODY=7BIT",
      " BODY=BINARYMIME",
      " BODY=",
      " SMTPUTF8",
      " SMTPUTF8=1",
      " AUTH=user@example.com",
      " AUTH=user+2Bplus@example.com",
      " AUTH=user+FF@example.com",
      " AUTH=+00x",
      " AUTH=<>",
      " AUTH=+ZZ",
      " AUTH=+",
      " AUTH=+A",
      " AUTH=",
      " AUTH=a+0Db",
      " SIZE=1 AUTH=<> SMTPUTF8 BODY=8BITMIME",
      " X-UNKNOWN=1",
      " SIZE=1 SIZE=2",
      " justjunk"
    ].freeze

    OTHER_COMMANDS = [
      "NOOP",
      "NOOP arg",
      "RSET",
      "RSET now",
      "VRFY user",
      "EXPN list",
      "HELP",
      "STARTTLS",
      "STARTTLS now",
      "DATA",
      "DATA now",
      "QUIT extra",
      "PROXY TCP4 1.2.3.4 5.6.7.8 1 2",
      "MAIL FROM:",
      "RCPT TO:",
      "MAIL",
      "RCPT TO",
      "mail from:<user@example.com>",
      "MAIL  FROM:<user@example.com>",
      " MAIL FROM:<user@example.com>",
      "WHATISTHIS",
      ""
    ].freeze

    # AUTH lines: the credential the fuzz server accepts, the two-step forms awaiting a
    # base64 continuation, an ungranted authzid claim, and base64 that will not decode.
    AUTH_COMMANDS = [
      "AUTH PLAIN AHVzZXIAc2VjcmV0",
      "AUTH PLAIN AHVzZXIAc2VjcmV0",
      "AUTH PLAIN",
      "AUTH LOGIN",
      "AUTH LOGIN dXNlcg==",
      "AUTH PLAIN dXNlcgB1c2VyAHNlY3JldA==",
      "AUTH PLAIN dmljdGltAHVzZXIAc2VjcmV0",
      "AUTH PLAIN AHVzZXIKAHNlY3JldA==",
      "AUTH FOOBAR",
      "AUTH",
      "AUTH PLAIN ****",
      "AUTH PLAIN #{"A" * 20_000}"
    ].freeze

    # Bare responses for whatever value state an AUTH command left behind — and
    # perfectly good garbage commands when it left none.
    CONTINUATIONS = [
      "AHVzZXIAc2VjcmV0",
      "dXNlcg==",
      "c2VjcmV0",
      "not base64!",
      "=",
      ""
    ].freeze

    BODY_LINES = [
      "Subject: fuzz",
      "From: <user@example.com>",
      "",
      "body",
      "..",
      ".leading dot",
      ".",
      "bare lf line\n",
      "bare cr line\r",
      "nul\x00in body",
      "high\xFFbyte",
      "x" * 1200
    ].freeze

    STEPS = %i[ mail mail rcpt rcpt transaction transaction data auth other continuation junk ].freeze

    def initialize(seed, pipelining: false)
      @random = Random.new(seed)
      @pipelining = pipelining
    end

    def payloads
      dialog = [ sample(GREETINGS) ]
      dialog << sample(AUTH_COMMANDS) if @random.rand(3).zero?
      @random.rand(4..12).times { dialog.concat(step) }
      dialog << "QUIT"
      dialog
    end

    private
      def step
        case sample(STEPS)
        when :mail then [ pipelined(envelope_command("MAIL FROM:")) ]
        when :rcpt then [ pipelined(envelope_command("RCPT TO:")) ]
        when :transaction then transaction
        when :data then data_step
        when :auth then [ sample(AUTH_COMMANDS) ]
        when :other then [ sample(OTHER_COMMANDS) ]
        when :continuation then [ sample(CONTINUATIONS) ]
        else [ junk ]
        end
      end

      # RFC 5321 §4.1.2 allows no space after the colon, but real senders leave
      # one and the engine tolerates it — fuzz both sides of that tolerance.
      def envelope_command(verb)
        "#{verb}#{sample([ "", " ", "  ", "\t" ])}#{sample(PATHS)}#{sample(PARAMETERS)}"
      end

      # A whole transaction, each command deliverable unless this is the turn it gets
      # mutated: independent draws earn a 503 before the parser gets interesting.
      def transaction
        [
          @random.rand(2).zero? ? envelope_command("MAIL FROM:") : "MAIL FROM:<user@example.com>",
          @random.rand(2).zero? ? envelope_command("RCPT TO:") : "RCPT TO:<user@example.com>",
          *data_step
        ]
      end

      def data_step
        [ "DATA", *Array.new(@random.rand(1..5)) { sample(BODY_LINES) }, "." ]
      end

      # One write carrying a second command behind the first. Only envelope and no-op
      # verbs join up: one that ends the session leaves the driver awaiting a reply.
      def pipelined(command)
        if @pipelining && @random.rand(5).zero?
          "#{command}\n#{sample([ "NOOP", "RSET", envelope_command("RCPT TO:"), "" ])}"
        else
          command
        end
      end

      # Bytes no grammar accounts for. LF is removed because it would frame a
      # second command the driver did not ask for; a trailing CR is left in.
      def junk
        @random.bytes(@random.rand(1..80)).delete("\n")
      end

      def sample(choices)
        choices[@random.rand(choices.size)]
      end
  end

  # The checked-in seed corpus, in the file format the README documents. A line
  # whose escapes end it with \n is written without the CRLF the driver appends.
  module FuzzCorpus
    DIRECTORY = File.expand_path("../fuzz/corpus", __dir__)
    ESCAPES = { "\\" => "\\", "r" => "\r", "n" => "\n", "t" => "\t", "0" => "\0" }.freeze

    class << self
      # Name and payloads for every corpus file, sorted so a failure reported on
      # one machine is found in the same place on another.
      def dialogs
        Dir.glob("*.txt", base: DIRECTORY).sort.map do |name|
          [ name, payloads(File.read(File.join(DIRECTORY, name), mode: "rb")) ]
        end
      end

      private
        def payloads(text)
          text.split("\n").reject { |line| line.start_with?("#") }.map { |line| decode(line) }
        end

        def decode(line)
          line.b.gsub(/\\(x\h\h|.)/) do
            escape = Regexp.last_match(1)
            escape.start_with?("x") ? escape[1, 2].hex.chr : ESCAPES.fetch(escape, escape)
          end
        end
    end
  end
end
