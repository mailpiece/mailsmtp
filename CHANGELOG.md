# Changelog

## Unreleased

- Added `min_data_rate` (default 500 bytes/s, `nil` disables), a minimum DATA rate past `read_timeout`, so a client dripping body lines can no longer hold a processing slot until `max_session_duration`

## 0.5.0 (2026-08-01)

- Initial Public Release