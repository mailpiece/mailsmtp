require_relative "test_helper"

class MailSmtp::BeforeBannerTest < MailSmtp::ServerIntegrationTest
  def test_runs_after_connected_and_before_the_banner
    server = start(BeforeBannerServer.new(**server_options(wait: 0)))

    socket = connect(port)

    assert_equal "220 before-banner ESMTP", read_smtp_response(socket).to_s.chomp
    assert_equal %i[ connected before_banner ], server.calls
  end

  def test_sees_what_a_client_sent_before_the_banner_and_leaves_it_for_the_engine
    server = start(BeforeBannerServer.new(**server_options))

    socket = connect(port)
    socket.print("EHLO early.example\r\n")

    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "EHLO early.example\r\n", server.peeked
  end

  def test_sees_the_client_named_by_proxy
    server = start(BeforeBannerServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ], wait: 0)))

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")

    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    assert_equal "203.0.113.9", server.remote_ip
  end

  # The header is the proxy's, not the client talking early: a peek starts behind it.
  def test_peeks_past_the_proxy_header
    server = start(BeforeBannerServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ])))

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\nEHLO early.example\r\n")

    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
    assert_equal "EHLO early.example\r\n", server.peeked
  end

  def test_peeks_nothing_behind_a_proxy_header_alone
    server = start(BeforeBannerServer.new(**server_options(proxy_hosts: [ "127.0.0.1" ], wait: 0.2)))

    socket = connect(port)
    socket.print("PROXY TCP4 203.0.113.9 10.0.0.1 12345 #{port}\r\n")

    assert_match(/\A220 /, read_smtp_response(socket).to_s)
    assert_nil server.peeked
  end

  def test_replies_with_a_raised_service_unavailable_and_closes
    server = start(BeforeBannerServer.new(**server_options(refuse: EarlyTalker)))

    socket = connect(port)
    socket.print("EHLO early.example\r\n")

    assert_equal "554 5.7.1 Protocol error: talking before the greeting", read_smtp_response(socket).to_s.chomp
    assert_nil socket.gets
    assert_equal %i[ connected before_banner ], server.calls
  end

  # As from +connected+: only a ServiceUnavailable carries its own reply this early.
  def test_replies_421_to_any_other_error_and_closes
    start(BeforeBannerServer.new(**server_options(refuse: RelayDenied)))

    socket = connect(port)
    socket.print("EHLO early.example\r\n")

    assert_match(/\A421 4\.3\.2 /, read_smtp_response(socket).to_s)
    assert_nil socket.gets
  end

  def test_the_default_hook_changes_nothing
    start_server

    socket = connect(port)
    socket.print("EHLO early.example\r\n")

    assert_equal "220 127.0.0.1 ESMTP", read_smtp_response(socket).to_s.chomp
    assert_match(/\A250 /, read_smtp_response(socket).to_s)
  end
end
