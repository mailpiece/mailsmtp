require_relative "test_helper"

class MailSmtp::ProxyTest < MailSmtp::ServerIntegrationTest
  def test_applies_proxy_source_ip_from_allowlisted_client
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    # no reply to PROXY itself, only the banner
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    socket.print("EHLO test.client.example\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  # The proxy speaks first, so the banner waits for it and is decided knowing the client.
  def test_waits_for_proxy_before_the_banner
    server = ConnectedRecordingServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ]))
    start(server)

    socket = connect(port)
    assert_nil IO.select([ socket ], nil, nil, 0.3)

    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    assert_equal "203.0.113.9", server.connected_remote_ip
  end

  # PROXY ports are decimal like every other port we read: a proxy that pads
  # them must not have "08" rejected or "010" read as 8.
  def test_reads_zero_padded_proxy_ports_as_decimal
    server = ProxyRecordingServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ]))
    start(server)

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 08025 00025\r\n")
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")

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
    socket.print("EHLO test.client.example\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  def test_refuses_a_proxy_header_longer_than_the_protocol_allows
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    socket.print("PROXY UNKNOWN #{"x" * 120}\r\n")

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
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")
    read_smtp_lines(socket)
    socket.print("RSET\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    socket.print("NOOP\r\n")
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_refuses_a_second_proxy_header
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # A stray header is dropped as one, not refused as pipelining.
  def test_refuses_a_second_proxy_header_with_a_line_behind_it
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    read_smtp_response(socket)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\nEHLO test.client.example\r\n")

    assert_match(/\A421 /, read_smtp_response(socket).to_s)
  end

  # The header is read before the banner, so it buys a client no pipelining after it.
  def test_refuses_a_pipelined_second_command_behind_proxy
    start_server(proxy_hosts: [ "127.0.0.1" ])

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\nNOOP\r\n")

    assert_match(/\A500 /, read_smtp_response(socket).to_s)
  end

  # PROXY belongs to the connection, not to what STARTTLS resets.
  def test_proxy_is_not_required_again_after_starttls
    start_server(proxy_hosts: [ "127.0.0.1" ], tls: FakeTls.new)

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")
    read_smtp_response(socket)
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
    socket.print("PROXY UNKNOWN\r\n")
    read_smtp_response(socket)
    socket.print("EHLO test.client.example\r\n")

    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end

  def test_proxy_defers_per_ip_cap_until_source_rewrite
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: 1)

    # Two connections from the load-balancer IP must both greet; per-IP applies
    # only after PROXY rewrites to distinct client addresses.
    first = connect(port)
    second = connect(port)
    first.print("PROXY TCP4 203.0.113.10 10.0.0.1 12345 #{port}\r\n")
    second.print("PROXY TCP4 203.0.113.11 10.0.0.1 12346 #{port}\r\n")
    assert_match(/\A220 /, read_smtp_response(first).to_s)
    assert_match(/\A220 /, read_smtp_response(second).to_s)

    first.print("EHLO a.example\r\n")
    assert_match(/\A250 /, read_smtp_response(first).to_s)
    second.print("EHLO b.example\r\n")
    assert_match(/\A250 /, read_smtp_response(second).to_s)
  end

  # Deferring the cap is not waiving it. A PROXY line that happens to declare
  # the peer's own address changes nothing, so it must still be enforced.
  def test_proxy_declaring_the_peers_own_address_is_still_capped
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: MAX_PER_IP)

    replies = Array.new(MAX_PER_IP + 1) do |index|
      socket = connect(port)
      socket.print("PROXY TCP4 127.0.0.1 127.0.0.1 1234#{index} #{port}\r\n")
      read_smtp_response(socket).to_s
    end

    assert_equal MAX_PER_IP, replies.count { |reply| reply.start_with?("220") }
    assert_equal 1, replies.count { |reply| reply.start_with?("421") }
  end

  # A host is normally handed a whole IPv6 /64, and an IPv4 client can arrive as
  # ::ffff:a.b.c.d, so the cap counts clients as the per-IP rates do.
  def test_the_per_ip_cap_counts_an_ipv6_client_by_its_64_and_a_mapped_ipv4_as_its_host
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: 1)

    replies = [
      "TCP6 2001:db8::1 ::1", "TCP6 2001:db8::2 ::1", "TCP6 2001:db8:0:1::1 ::1",
      "TCP4 192.0.2.7 127.0.0.1", "TCP6 ::ffff:192.0.2.7 ::1"
    ].map do |endpoints|
      socket = connect(port)
      socket.print("PROXY #{endpoints} 40000 #{port}\r\n")
      read_smtp_response(socket).to_s[0, 3]
    end

    assert_equal %w[ 220 421 220 220 421 ], replies
  end

  # PROXY UNKNOWN names no client for the cap to move to, so it falls back on
  # the peer rather than leaving the connection exempt for good.
  def test_proxy_unknown_applies_the_per_ip_cap_to_the_peer
    start_server(proxy_hosts: [ "127.0.0.1" ], max_connections_per_ip: MAX_PER_IP)

    replies = Array.new(MAX_PER_IP + 1) do
      socket = connect(port)
      socket.print("PROXY UNKNOWN\r\n")
      read_smtp_response(socket).to_s
    end

    assert_equal MAX_PER_IP, replies.count { |reply| reply.start_with?("220") }
    assert_equal 1, replies.count { |reply| reply.start_with?("421") }
  end
end
