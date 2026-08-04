# mailsmtp

📬 A boring SMTP server for Ruby.

Receive emails in Ruby with your own logic plugged in. **mailsmtp** handles the SMTP protocol — AUTH, MAIL FROM, RCPT TO, DATA — so you just write the part that matters.

Use it anywhere you need to accept mail directly instead of going through a hosted inbound service: self-hosted mail receipt, a replacement for inbound-parse webhooks, test/fixture SMTP servers, or feeding mail into a custom pipeline.

**mailsmtp** handles:

- the protocol — AUTH, MAIL FROM, RCPT TO, DATA, STARTTLS, PIPELINING
- streaming — `receive` gets a live `io` into the DATA stream, so nothing buffers the whole message
- size limits — SIZE is advertised and enforced as DATA arrives
- smuggling protection — bare LF and bare CR in DATA are rejected by default
- backpressure — concurrent DATA transfers are capped, with a queue and timeout
- hot reloading — swap the STARTTLS certificate without restarting

Plus:

- subclass-and-override hooks for every verb
- raise a typed error to choose the SMTP reply
- multi-listen across any number of host×port pairs
- injectable logger and live connection/processing counters



## Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
- [Design](#design)
  - [Role — the server side](#role--the-server-side)
  - [Hooks — subclass verbs](#hooks--subclass-verbs)
  - [DATA — live reader into receive](#data--live-reader-into-receive)
- [Reference](#reference)
  - [Hooks](#hooks)
  - [Errors](#errors)
  - [Session and Envelope](#session-and-envelope)
  - [Options](#options)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [License](#license)



## Installation

Add this line to your application's Gemfile:

```ruby
gem "mailsmtp"
```

Requires Ruby >= 3.4

## Getting Started

Subclass `MailSmtp::Server` and override whichever hooks you care about.

```ruby
require "mailsmtp"

class MyServer < MailSmtp::Server
  def connected(session)
    session.banner = "mail.example.com ESMTP"
    session.greeting = "mail.example.com"
  end

  def authenticate(session, username:, password:, authorization_id: "")
    raise MailSmtp::AuthenticationFailed unless username == "user" && password == "secret"
    username # granted as session.authorization_id
  end

  def mail_from(session, address)
    address # "<a@example.com>" arrives unwrapped as "a@example.com", "<>" as ""
  end

  def rcpt_to(session, address)
    address
  end

  def receive(session, io)
    # Prefer streaming — io.read materializes the whole message in memory.
    IO.copy_stream(io, storage_destination)
  end
end
```

And start it:

```ruby
server = MyServer.new(
  host: "127.0.0.1",
  port: 2525,
  tls: nil,
  auth: :disabled,
  starttls: :optional,
  max_connections: 100,
  max_processings: 4,
  max_message_size: 10_485_760,
  max_recipients: 100,
  read_timeout: 300,
  write_timeout: 30,
  handshake_timeout: 30
)
server.start
```

`tls:` takes an `OpenSSL::SSL::SSLContext`, built like any other Ruby TLS server:

```ruby
tls_context = OpenSSL::SSL::SSLContext.new
tls_context.cert = OpenSSL::X509::Certificate.new(File.read("cert.pem"))
tls_context.key = OpenSSL::PKey::RSA.new(File.read("key.pem"))

server = MyServer.new(host: "127.0.0.1", port: 2525, tls: tls_context,
  auth: :disabled, starttls: :optional, max_connections: 100, max_processings: 4)
```

You can hot-swap the STARTTLS certificate without restarting — e.g. after a renewal replaces `cert.pem`/`key.pem`:

```ruby
server.tls = new_tls_context
```

For multi-listen, `hosts:` / `ports:` expand to every host×port pair.

Or bind the sockets yourself and hand them over. `listeners:` replaces `host:` / `port:` (you can't pass both), so you're free to use port 0 and check `#addresses` to see where the kernel actually put you. The server takes ownership — `stop` closes the sockets, and a restart binds fresh ones.

```ruby
listener = TCPServer.new("127.0.0.1", 0)
server = MyServer.new(listeners: [ listener ], tls: nil, auth: :disabled, starttls: :optional,
  max_connections: 100, max_processings: 4)
server.start
server.addresses # => ["127.0.0.1:38109"]
```



## Design



### Role — the server side

mailsmtp speaks the server side of SMTP. Sending is out of scope — use `Net::SMTP`, your MTA, or Action Mailer.

### Hooks — subclass verbs

Subclass `MailSmtp::Server` and override the hooks you need: `authenticate`, `auth_mechanisms`, `mail_from`, `rcpt_to`, `receive` — plus `build_session` / `process_line` if you want a custom session or command gate.

One server object owns policy. `Session` just holds connection state (envelope, auth) — it's not a second interface you implement. See [Session and Envelope](#session-and-envelope) for its full shape, including the `phase` symbols `process_line` dispatches on. Raise a `MailSmtp::Error` subclass to choose the SMTP reply.

### DATA — live reader into receive

After `354`, the engine builds a `DataReader` over the socket (dot-unstuffing, SIZE, line limits) — wrapped in a `PrefixedReader` when `add_received: true` prepends the Received header — and calls `receive(session, io)`. Both are `IO`-shaped (`read`, `readpartial`, `eof?`, `binmode`, `close`, `closed?`) and safe to hand to `IO.copy_stream`; which one `io` actually is is an implementation detail. Prefer `IO.copy_stream` (or chunked reads); the engine **drains** through `.` then sends **one** reply — except when SIZE/`MessageTooLarge` (or the drain byte ceiling) forces a close after the error reply (no unbounded drain).

```ruby
def receive(session, io)
  IO.copy_stream(io, storage_destination)
  # or: while (chunk = io.read(8192)); ...; end  — read(len) returns nil at EOF
end
```

SIZE / line-length failures raise a `MailSmtp::Error` from `read` / `readpartial` (not a short successful body). Mid-DATA disconnect raises `ServiceUnavailable`. If `receive` ignores the io, the reply still comes from the reader's failure after drain.

## Reference



### Hooks

Raising a `MailSmtp::Error` subclass sends that SMTP reply to the client. Other exceptions during `receive` become a 451 (`LocalError`). Unexpected errors outside DATA still need cleanup (prefer raising a defined error).

Every `MailSmtp::Error` subclass answers `unrecoverable?` (`false` unless overridden), which decides what happens after its reply is sent: recoverable errors (the default) leave the session open — inside DATA, the body is still drained to its terminating `.` so the next command reads cleanly. An unrecoverable error closes the connection after the reply instead. The built-in `BareNewline`, `BareCarriageReturn`, and `MessageTooLarge` override it to `true`, because a client whose framing is already in question (or who has been told SIZE was exceeded, per RFC 5321 §4.5.3.1.7) cannot be trusted to still be in sync for a next command. An application-defined error subclass is recoverable by default; override `unrecoverable?` to end the connection instead:

```ruby
class BlockedSender < MailSmtp::Error
  status 550, "Sender is blocked", enhanced: "5.7.1"
  def unrecoverable? = true
end
```


| Hook                | Signature                                            | Return / raise                                                                                                                                                                                                |
| ------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connected`         | `(session)`                                          | —                                                                                                                                                                                                             |
| `disconnected`      | `(session)`                                          | —                                                                                                                                                                                                             |
| `helo`              | `(session, name)`                                    | after STARTTLS, `session.tls_version` / `session.tls_cipher` are set                                                                                                                                          |
| `proxy`             | `(session, proxy_data)`                              | hash replaces PROXY data                                                                                                                                                                                      |
| `authenticate`      | `(session, username:, password:, authorization_id:)` | returned String grants that `authorization_id`, else the username is used; raise `AuthenticationFailed`                                                                                                       |
| `auth_mechanisms`   | `(session)`                                          |                                                                                                                                                                                                               |
| `mail_from`         | `(session, address)`                                 | address is the mailbox out of the reverse-path as a UTF-8 String (`""` for `<>`, see `envelope.null_sender?`), with any `AUTH=` claim on `envelope.auth_identity`; returned string is stored as envelope from |
| `rcpt_to`           | `(session, address)`                                 | address is the mailbox out of the forward-path, a UTF-8 String; returned string is appended to envelope to                                                                                                    |
| `receiving_started` | `(session)`                                          | once, before `receive`                                                                                                                                                                                        |
| `headers_received`  | `(session)`                                          | when the header/body blank line is seen while reading                                                                                                                                                         |
| `receive`           | `(session, io)`                                      | read the `io` — a `DataReader`, or a `PrefixedReader` wrapping one when `add_received: true` (or discard it); raise to reject                                                                                 |
| `received_header`   | `(session)`                                          | string prefixed onto the reader when `add_received: true`                                                                                                                                                     |
| `build_session`     | `()`                                                 | a `Session` (or subclass)                                                                                                                                                                                     |
| `process_line`      | `(session, line)`                                    | override for policy; call `super` for dispatch — dispatches on `session.phase` ([Session and Envelope](#session-and-envelope))                                                                                |
| `unknown_command`   | `(session, line)`                                    | default raises `CommandNotRecognized`                                                                                                                                                                         |
| `log`               | `(session, severity, msg, err:)`                     | —                                                                                                                                                                                                             |




### Errors

Every built-in error the engine itself can raise. Raise any of these from a hook to send that reply; `unrecoverable?` is `true` only where noted (see above) — everything else leaves the session open.


| Error                            | Status | Enhanced | Message                                                           | Unrecoverable |
| -------------------------------- | ------ | -------- | ----------------------------------------------------------------- | ------------- |
| `ServiceUnavailable`             | 421    | 4.3.2    | Service not available, closing transmission channel               |               |
| `ConnectionLost`                 | 421    | 4.3.2    | (as `ServiceUnavailable`) — peer gone before a reply could arrive |               |
| `LocalError`                     | 451    | 4.3.0    | Requested action aborted: local error in processing               |               |
| `TooManyRecipients`              | 452    | 4.5.3    | Requested action not taken: too many recipients                   |               |
| `CommandNotRecognized`           | 500    | 5.5.1    | Syntax error, command unrecognized                                |               |
| `LineTooLong`                    | 500    | 5.5.2    | Line too long                                                     |               |
| `PipeliningNotSupported`         | 500    | 5.5.2    | Pipelining is not supported; commands must be sent one at a time  |               |
| `InvalidParameters`              | 501    | 5.5.4    | Syntax error in parameters or arguments                           |               |
| `CommandNotImplemented`          | 502    | 5.5.1    | Command not implemented                                           |               |
| `BadSequence`                    | 503    | 5.5.1    | Bad sequence of commands                                          |               |
| `AuthenticationTypeNotSupported` | 504    | 5.5.4    | Unrecognized authentication type                                  |               |
| `EncryptionRequired`             | 530    | 5.7.0    | Must issue a STARTTLS command first                               |               |
| `AuthenticationRequired`         | 530    | 5.7.0    | Authentication required                                           |               |
| `AuthenticationFailed`           | 535    | 5.7.8    | Authentication credentials invalid                                |               |
| `BareNewline`                    | 550    | 5.5.2    | Bare LF disallowed; lines must end with CRLF                      | ✓             |
| `BareCarriageReturn`             | 550    | 5.5.2    | Bare CR disallowed; lines must end with CRLF                      | ✓             |
| `MessageTooLarge`                | 552    | 5.3.4    | Requested mail action aborted: exceeded storage allocation        | ✓             |
| `ParametersNotRecognized`        | 555    | 5.5.4    | MAIL FROM/RCPT TO parameters not recognized or not implemented    |               |


All descend from `MailSmtp::Error`, so `rescue MailSmtp::Error` catches any of them (e.g. from code shared between hooks). Define your own the same way — see the `BlockedSender` example above.

### Session and Envelope

Every hook receives the `Session` for the connection. It carries the protocol phase, the connection's identity and TLS state, and the current message's `Envelope` — reset between messages, not between connections.

#### Phase

`session.phase` is what `process_line`'s default implementation (and `Server#process_command_line`) dispatches on. A custom `process_line` that calls `super` sees the same symbol; one that doesn't still has it available for its own gating.


| Phase              | Meaning                                                                                                                                         |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `:helo`            | Before HELO/EHLO is accepted — the very first phase, and again right after a STARTTLS handshake completes (RFC 3207 §4.2 requires a fresh HELO) |
| `:ready`           | HELO/EHLO (or RSET) done; ready for AUTH, MAIL FROM, or STARTTLS                                                                                |
| `:mail`            | MAIL FROM accepted; envelope open, awaiting the first RCPT TO                                                                                   |
| `:rcpt`            | At least one RCPT TO accepted; further RCPT TO or DATA is allowed                                                                               |
| `:data`            | Inside the DATA transfer, streaming to `receive`; back to `:ready` once it completes                                                            |
| `:starttls`        | Set by the STARTTLS command; consumed by the engine to run the TLS handshake before the next read                                               |
| `:quit`            | QUIT accepted; the engine sends the closing `221` and ends the session                                                                          |
| `:auth_plain`      | Mid `AUTH PLAIN` with no initial response; the next line is the base64 credential                                                               |
| `:auth_login_user` | Mid `AUTH LOGIN`; the next line is the base64 username                                                                                          |
| `:auth_login_pass` | Mid `AUTH LOGIN`, username received; the next line is the base64 password                                                                       |


The three `auth_*` phases are also where the engine widens the line-length limit to `MAX_AUTH_LINE_LENGTH` and redacts the DEBUG log line, since the "line" is a credential.

#### Session


| Accessor                                                                | Notes                                                                                                                      |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `phase`                                                                 | current phase symbol — see above                                                                                           |
| `local_ip` / `remote_ip`                                                | connection endpoints; `remote_ip` is overwritten by a valid PROXY line                                                     |
| `helo`                                                                  | the HELO/EHLO name the client gave (unsafe characters neutered to `?`); `nil` before HELO                                  |
| `banner`                                                                | the `220` greeting text; settable from `connected` (README example), defaults to `"#{local_ip} ESMTP"`                     |
| `greeting`                                                              | server name echoed in the EHLO response and used in the Received header; settable from `connected`, defaults to `local_ip` |
| `connected_at` / `encrypted_at` / `authenticated_at`                    | UTC `Time` when each happened, or `nil`                                                                                    |
| `authenticated?` / `encrypted?`                                         | `true` once the matching `_at` above is set                                                                                |
| `authorization_id` / `authentication_id` / `requested_authorization_id` | identities from a granted or attempted AUTH (see `authenticate`'s row above)                                               |
| `exceptions` / `auth_failures`                                          | counters toward `max_exceptions` / `max_auth_failures`                                                                     |
| `proxy`                                                                 | the (possibly hook-replaced) PROXY v1 data hash, or `nil` when PROXY is off or unsent                                      |
| `close_after_reply`                                                     | when `true`, the session ends after the reply currently being sent                                                         |
| `tls_version` / `tls_cipher`                                            | set once STARTTLS's handshake completes                                                                                    |
| `envelope`                                                              | the current message's `Envelope` — see below                                                                               |


`auth_login_username` is also a public accessor, but it's the engine's own scratch space between the two lines of `AUTH LOGIN` — nothing in an application hook needs to read it.

#### Envelope (`session.envelope`)

Reset at `session.reset` — after HELO/EHLO, RSET, DATA completing, and STARTTLS's forced reset — so it always describes only the message in progress.


| Accessor        | Notes                                                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `from`          | mailbox from MAIL FROM (`""` for the null reverse-path `<>`; `nil` before MAIL FROM); see `null_sender?`                            |
| `to`            | Array of accepted RCPT TO mailboxes, in RCPT order                                                                                  |
| `body_encoding` | `:seven_bit`, `:eight_bit_mime`, or `nil` (no BODY= given), from the `BODY=` parameter — requires `eight_bit_mime: true`            |
| `declared_size` | Integer from `SIZE=`, or `nil` if the client didn't send it                                                                         |
| `smtputf8`      | `true` if this MAIL FROM carried the `SMTPUTF8` parameter, else `nil` (never `false`) — requires `smtputf8: true`                   |
| `auth_identity` | decoded `AUTH=` claim from MAIL FROM (RFC 4954 §5) — `nil` if none was sent, `""` for the `<>` form; a claim, never a verified fact |
| `null_sender?`  | `true` when `from == ""`                                                                                                            |




### Options


| Option                   | Default             | Notes                                                                                                                                                                                   |
| ------------------------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`                   | required arg        | `:disabled` or `:required`                                                                                                                                                              |
| `eight_bit_mime`         | `false`             | RFC 6152; what the client declared on a given message lands on `session.envelope.body_encoding`                                                                                         |
| `smtputf8`               | `false`             | RFC 6531; requires `eight_bit_mime`. When off, non-ASCII envelope addresses are refused; when on, invalid UTF-8 ones are. What the client declared lands on `session.envelope.smtputf8` |
| `pipelining`             | `false`             | RFC 2920; STARTTLS always drops plaintext buffers                                                                                                                                       |
| `proxy_hosts`            | `[]`                | PROXY v1 from these IPs/CIDRs                                                                                                                                                           |
| `add_received`           | `false`             | Prefix `received_header` onto the DATA reader                                                                                                                                           |
| `forbid_bare_newline`    | `true`              | Reject DATA lines carrying a bare LF or a bare CR (SMTP smuggling)                                                                                                                      |
| `strict_path`            | `true`              | Require angle brackets on the envelope path; `false` also takes a bare path, ending it at the first space                                                                               |
| `max_message_size`       | `10485760` (10 MiB) | Advertises SIZE and enforces as DATA arrives; `nil` disables                                                                                                                            |
| `max_recipients`         | `100`               | Minimum 100 (RFC 5321); enforced at RCPT TO                                                                                                                                             |
| `max_connections`        | required arg        | Concurrent connections; refused with a 421 in the acceptor, before a thread is spawned                                                                                                  |
| `max_connections_per_ip` | `nil`               | Per-IP concurrent connections; `nil` disables. Enforced once the peer is known, so after a PROXY line                                                                                   |
| `max_processings`        | required arg        | Concurrent DATA transfers; idle sessions do not consume a slot                                                                                                                          |
| `max_processings_wait`   | `30`                | Seconds to wait for a DATA processing slot before 421                                                                                                                                   |
| `max_auth_failures`      | `3`                 | Failed AUTH attempts before 421; `nil` disables                                                                                                                                         |
| `max_exceptions`         | `20`                | Protocol errors before 421; `nil` disables                                                                                                                                              |
| `read_timeout`           | `300`               | Idle read timeout (seconds); RFC 5321 §4.5.3.2.7; `nil` disables                                                                                                                        |
| `write_timeout`          | `30`                | Reply write timeout (seconds)                                                                                                                                                           |
| `handshake_timeout`      | `30`                | STARTTLS handshake timeout (seconds); independent of `read_timeout`; `nil` falls back to 30                                                                                             |
| `max_session_duration`   | `1800`              | Absolute session ceiling (seconds); `nil` to disable                                                                                                                                    |
| `pending_input_limit`    | `1048576` (1 MiB)   | Ceiling on bytes buffered behind a line (command or DATA body) not yet terminated; overrun closes the connection                                                                        |
| `logger`                 | stdout logger       | Injectable `Logger`                                                                                                                                                                     |
| `logger_severity`        | `Logger::INFO`      | Level for the built-in stdout logger; passing it together with `logger` raises `ArgumentError` — set the level on your own logger instead                                               |


`starttls: :required` requires a non-nil `tls` object. Per-IP connection caps are deferred for peers in `proxy_hosts` until PROXY rewrites the client address. Forced `#stop` aborts lingering sockets with RST (`SO_LINGER 0`). Inspect live load with `connections_count` / `processings_count` (and `connections?`).

A forced `#stop` raises `MailSmtp::Server::StopConnection` into any connection still working — including one sitting inside your `receive`. It descends from `Exception`, not `StandardError`, so a `rescue StandardError` wrapped around a storage call won't swallow it and stall the shutdown. If you do catch it — a bare `rescue Exception`, or to record a partial write — re-raise it; a connection that keeps hold of its stop is abandoned and its socket reset once the drain grace expires.

## Testing

```sh
bundle install
rake
```



## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mailsmtp/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features



## Acknowledgments

View the [acknowledgments](ACKNOWLEDGMENTS.md).

## License

MIT. See [LICENSE](LICENSE).