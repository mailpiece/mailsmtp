require "ipaddr"

module MailSmtp
  # The client an address counts as, for every per-IP cap and rate. An IPv6 client
  # counts by its /64, the block a single host is normally handed, so hopping across
  # its addresses does not start the count over; IPv4 counts as is.
  module ClientKey
    def self.of(address)
      ip = IPAddr.new(address)
      # A dual-stack listener reports IPv4 clients as ::ffff:a.b.c.d, which masked to
      # a /64 would put all of them in one bucket.
      ip = ip.native if ip.ipv4_mapped?
      ip.ipv6? ? ip.mask(64).to_s : ip.to_s
    rescue IPAddr::Error
      address
    end
  end
end
