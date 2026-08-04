require_relative "test_helper"

class MailSmtp::ProxyTest < MailSmtp::ServerIntegrationTest
  def test_applies_proxy_source_ip_from_allowlisted_client
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    # no reply
    socket.print("EHLO test.client.example\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  # PROXY ports are decimal like every other port we read: a proxy that pads
  # them must not have "08" rejected or "010" read as 8.
  def test_reads_zero_padded_proxy_ports_as_decimal
    server = ProxyRecordingServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ]))
    start(server)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 08025 00025\r\nEHLO test.client.example\r\n")

    assert_match(/\A250 /, read_smtp_lines(socket).last.to_s)
    assert_equal 8025, server.proxy_data[:source_port]
    assert_equal 25, server.proxy_data[:dest_port]
  end

  def test_rejects_proxy_from_non_allowlisted_client
    start_server(proxy_hosts: [ "10.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # An allowlisted peer must send PROXY before anything else, or the cap exemption never expires.
  def test_requires_proxy_before_any_other_command_from_an_allowlisted_client
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_does_not_require_proxy_from_a_peer_that_is_not_allowlisted
    start_server(proxy_hosts: [ "10.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  # PROXY is required once per connection, not once per command.
  def test_proxy_is_required_only_once_per_connection
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("RSET\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("NOOP\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  # PROXY belongs to the connection, not to what STARTTLS resets.
  def test_proxy_is_not_required_again_after_starttls
    start_server(proxy_hosts: [ "127.0.0.1" ], tls: FakeTls.new)

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("STARTTLS\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)

    socket.print("EHLO test.client.example\r\n")
    assert_match(/\A250 /, read_smtp_lines(socket).last.to_s)
  end

  # PROXY UNKNOWN names no client, but it is still the preamble having arrived.
  def test_proxy_unknown_satisfies_the_requirement
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    read_smtp_response(socket)
    socket.print("PROXY UNKNOWN\r\n")
    socket.print("EHLO test.client.example\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_proxy_defers_per_ip_cap_until_source_rewrite
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: 1)

    # Two connections from the load-balancer IP must both greet; per-IP applies
    # only after PROXY rewrites to distinct client addresses.
    first = connect(port)
    second = connect(port)
    assert_match(/\A220 /, read_smtp_response(first).to_s)
    assert_match(/\A220 /, read_smtp_response(second).to_s)

    first.print("PROXY TCP4 203.0.113.10 10.0.0.1 12345 #{port}\r\n")
    first.print("EHLO a.example\r\n")
    assert_match(/\A250 /, read_smtp_response(first).to_s)

    second.print("PROXY TCP4 203.0.113.11 10.0.0.1 12346 #{port}\r\n")
    second.print("EHLO b.example\r\n")
    assert_match(/\A250 /, read_smtp_response(second).to_s)
  end

  # Deferring the cap is not waiving it. A PROXY line that happens to declare
  # the peer's own address changes nothing, so it must still be enforced.
  def test_proxy_declaring_the_peers_own_address_is_still_capped
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: MAX_PER_IP)

    replies = Array.new(MAX_PER_IP + 1) do |index|
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("PROXY TCP4 127.0.0.1 127.0.0.1 1234#{index} #{port}\r\nEHLO a#{index}.example\r\n")
      read_smtp_lines(socket).last.to_s
    end

    assert_equal MAX_PER_IP, replies.count { |reply| reply.start_with?("250") }
    assert_equal 1, replies.count { |reply| reply.start_with?("421") }
  end

  # PROXY UNKNOWN names no client for the cap to move to, so it falls back on
  # the peer rather than leaving the connection exempt for good.
  def test_proxy_unknown_applies_the_per_ip_cap_to_the_peer
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: MAX_PER_IP)

    replies = Array.new(MAX_PER_IP + 1) do |index|
      socket = connect(port)
      read_smtp_response(socket)
      socket.print("PROXY UNKNOWN\r\nEHLO a#{index}.example\r\n")
      read_smtp_lines(socket).last.to_s
    end

    assert_equal MAX_PER_IP, replies.count { |reply| reply.start_with?("250") }
    assert_equal 1, replies.count { |reply| reply.start_with?("421") }
  end
end
