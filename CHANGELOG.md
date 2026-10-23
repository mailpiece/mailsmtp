# Changelog

## 0.7.0

- Added `max_messages_per_ip`, `max_tls_sessions_per_ip` and `max_auth_attempts_per_ip` (`nil` disables), per-minute caps on one client address: 450 at MAIL FROM, 454 at STARTTLS and AUTH
- Added `stress_threshold` (`nil` disables): with that share of `max_connections` admitted, timeouts drop to 10 seconds and one protocol error ends a session
- Added `error_sleep_after` (`nil` disables) and `error_sleep_time` (default 1): past that many errors, each error reply waits first

## 0.6.0

- Added `min_data_rate` (default 500 bytes/s, `nil` disables), a minimum DATA rate past `read_timeout`, so a client dripping body lines can no longer hold a processing slot until `max_session_duration`

## 0.5.0 (2026-08-01)

- Initial Public Release