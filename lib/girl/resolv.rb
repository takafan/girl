##
# usage
# =====
#
# 1. Girl::Resolvd.new( 7070 ).looping # @server
#
# 2. Girl::Resolv.new( 1717, [ '114.114.114.114' ], 'your.server.ip', 7070, [ 'google.com' ] ).looping # @home
#
# 3. dig google.com @127.0.0.1 -p1717
#
require 'socket'

module Girl
  class Resolv

    def initialize( port = 1717, nameservers = [], resolvd_host = nil, resolvd_port = nil, custom_domains = [] )
      pub_socks = {} # nameserver => sock
      rvd_socks = {} # resolvd => sock
      pub_addrs = []
      rvd_addrs = []
      pub_addr6s = []
      rvd_addr6s = []

      if nameservers.empty?
        nameservers = %w[ 114.114.114.114 114.114.115.115 ]
      end

      nameservers.each do | ip |
        addr = Socket.sockaddr_in( 53, ip )

        if Addrinfo.udp( ip, 53 ).ipv6?
          pub_addr6s << addr
        else
          pub_addrs << addr
        end
      end

      if resolvd_host && resolvd_port
        addr = Socket.sockaddr_in( resolvd_port, resolvd_host )

        if Addrinfo.udp( resolvd_host, resolvd_port ).ipv6?
          rvd_addr6s << addr
        else
          rvd_addrs << addr
        end
      end

      @reads = []

      begin
        sock4 = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        sock4.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        sock4.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
        puts "bound on #{ port } AF_INET"

        @reads << sock4

        pub_addrs.each do | addr |
          pub_socks[ addr ] = sock4
        end

        rvd_addrs.each do | addr |
          rvd_socks[ addr ] = sock4
        end
      rescue Errno::EAFNOSUPPORT => e
        puts "AF_INET #{ e.class }"
      end

      begin
        sock6 = Socket.new( Socket::AF_INET6, Socket::SOCK_DGRAM, 0 )
        sock6.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        sock6.bind( Socket.sockaddr_in( port, '::0' ) )
        puts "bound on #{ port } AF_INET6"

        @reads << sock6

        pub_addr6s.each do | addr |
          pub_socks[ addr ] = sock6
        end

        rvd_addr6s.each do | addr |
          rvd_socks[ addr ] = sock6
        end
      rescue Errno::EAFNOSUPPORT => e
        puts "AF_INET6 #{ e.class }"
      end

      @pub_socks = pub_socks
      @rvd_socks = rvd_socks
      @custom_qnames = custom_domains.map{ |dom| dom.split( '.' ).map{ | sub | [ sub.size ].pack( 'C' ) + sub }.join }
      @ids = {}
      @caches = {}
    end

    def looping
      loop do
        readable_socks, _ = IO.select( @reads )
        readable_socks.each do | sock |
          # https://tools.ietf.org/html/rfc1035#page-26
          data, addrinfo, rflags, *controls = sock.recvmsg
          sender = addrinfo.to_sockaddr

          if data.size <= 12
            puts 'missing header?'
            next
          end

          id = data[ 0, 2 ]
          qr = data[ 2, 2 ].unpack( 'B16' ).first[ 0 ]
          qname_len = data[ 12..-1 ].index([ 0 ].pack( 'C' ))

          unless qname_len
            puts 'missing qname?'
            next
          end

          if qr == '0'
            qname = data[ 12, qname_len ]
            question = data[ 12, qname_len + 5 ]
            cache, ttl_ix, expire = @caches[ question ]

            if cache
              now = Time.new

              if expire > now
                cache[ 0, 2 ] = id
                cache[ ttl_ix, 4 ] = [ ( expire - now ).to_i ].pack( 'N' )

                begin
                  sock.sendmsg( cache, 0, sender )
                rescue Errno::ENETUNREACH => e
                  puts "#{ now } send cache #{ e.class }"
                end

                next
              else
                @caches.delete( question )
              end
            end

            is_custom = @custom_qnames.any?{ | custom | qname.include?( custom ) }

            if is_custom
              @rvd_socks.each do | sockaddr, alias_sock |
                data[ 12, qname_len ] = swap( qname )

                begin
                  alias_sock.sendmsg( data, 0, sockaddr )
                rescue Errno::ENETUNREACH => e
                  puts "#{ Time.new } send rvd #{ e.class }"
                end
              end
            else
              @pub_socks.each do | sockaddr, alias_sock |
                begin
                  alias_sock.sendmsg( data, 0, sockaddr )
                rescue Errno::ENETUNREACH => e
                  puts "#{ Time.new } send pub #{ e.class }"
                end
              end
            end

            @ids[ id ] = [ sender, is_custom, sock ]
          elsif qr == '1' && @ids.include?( id )
            # relay the fastest response, ignore followings
            src, is_custom, alias_sock = @ids.delete( id )
            ancount = data[ 6, 2 ].unpack( 'n' ).first
            nscount = data[ 8, 2 ].unpack( 'n' ).first

            if is_custom
              qname = swap( data[ 12, qname_len ] )
              data[ 12, qname_len ] = qname
            else
              qname = data[ 12, qname_len ]
            end

            begin
              alias_sock.sendmsg( data, 0, src )
            rescue Errno::ENETUNREACH => e
              puts "#{ Time.new } send client #{ e.class }"
            end

            next if ancount == 0 && nscount == 0

            # move to first RR = Header (12) + QNAME + 0x00 + QTYPE (2) + QCLASS (2)
            ix = 17 + qname_len

            ttls = []
            now = Time.new

            ( ancount + nscount ).times do | i |
              unless data[ix]
                puts "nil answer? #{ i } of #{ ancount + nscount } RR #{ data.inspect }"
                break
              end

              loop do
                if data[ ix ].unpack( 'B8' ).first[ 0, 2 ] == '11' # pointer
                  # move to TTL
                  ix += 6
                  break
                else
                  len = data[ ix ].unpack( 'C' ).first
                  if len == 0
                    # move to TTL
                    ix += 5
                    break
                  end
                  # move to next label
                  ix += ( len + 1 )
                end
              end

              ttls << [ ix, now + data[ ix, 4 ].unpack( 'N' ).first ]

              # move to next RR = TTL(4) + RDLENGTH(2) + RDATA
              ix += ( 6 + data[ ix + 4, 2 ].unpack( 'n' ).first )
            end

            next if ttls.empty?

            # cache data and set expire by shortest TTL
            question = qname + data[ 12 + qname_len, 5 ]
            @caches[ question ] = [ data, *ttls.sort_by{ | _, exp | exp }.first ]
          end
        end
      end
    end

    def swap( data )
      # overwrite me, you'll be free
      data
    end

    def quit!
      @reads.each{ | sock | sock.close }
      exit
    end

  end
end
