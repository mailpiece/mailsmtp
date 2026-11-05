# Changelog

## Unreleased

- Changed: with `auth` on, a MAIL FROM line may run to 1012 octets, room for its AUTH= parameter (RFC 4954 §5)
- Added the `before_banner(session, io)` hook, called with the client's socket before the banner
- Changed: a peer in `proxy_hosts` now gets no banner until it sends its PROXY header
- Changed: with `proxy_hosts` set, a client may no longer pipeline behind its first command unless `pipelining` is on
- Added hooks to observe refused connections, the error tarpit and every reply
- Changed: refused commands, timeouts and a client's failed TLS now log at INFO, and the server out of capacity at WARN (`ServerBusy`), leaving ERROR for hook and server faults
- Fixed: a `.` after a bare LF no longer ends DATA, and a bare LF behind a long line or an error from `receive` closes the connection
- Fixed: under stress, `min_data_rate`'s grace drops to 10 seconds with the idle timeout
- Fixed: a connection thread that cannot be started no longer stops the listener; it backs off as it does when out of descriptors
- Fixed: a command line past `pending_input_limit` gets a 421 logged at INFO, not an ERROR
- Fixed: `false` from `authenticate` refuses the login with a 535 instead of authenticating
- Changed: a control character or DEL in a MAIL FROM or RCPT TO mailbox is refused with a 501
- Changed: a client's command logs at DEBUG with control characters as `?`, as Postfix's `printable()`
- Changed: `max_connections_per_ip` counts an IPv6 client by its /64 and `::ffff:a.b.c.d` as `a.b.c.d`, as the per-IP rates do
- Added `max_processings_per_ip` (`nil` disables): past it, DATA gets a 451 (`TooManyProcessings`) instead of waiting for a slot
- Added `max_junk_commands` (default 100, Postfix's `smtpd_junk_command_limit`, 1 under stress): past it, each NOOP, RSET, VRFY or repeated HELO/EHLO counts toward `max_exceptions`

## 0.7.0

- Added `max_messages_per_ip`, `max_tls_sessions_per_ip` and `max_auth_attempts_per_ip` (`nil` disables), per-minute caps on one client address: 450 at MAIL FROM, 454 at STARTTLS and AUTH
- Added `stress_threshold` (`nil` disables): with that share of `max_connections` admitted, timeouts drop to 10 seconds and one protocol error ends a session
- Added `error_sleep_after` (`nil` disables) and `error_sleep_time` (default 1): past that many errors, each error reply waits first

## 0.6.0

- Added `min_data_rate` (default 500 bytes/s, `nil` disables), a minimum DATA rate past `read_timeout`, so a client dripping body lines can no longer hold a processing slot until `max_session_duration`

## 0.5.0 (2026-08-01)

- Initial Public Release