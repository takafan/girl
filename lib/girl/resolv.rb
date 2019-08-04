require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Resolv - dns查询得到正确的ip。近端。
#
# usage
# =====
#
# Girl::Resolvd.new( 7070 ).looping # 远端
#
# Girl::Resolv.new( 1717, [ '114.114.114.114' ], 'your.server.ip', 7070, [ 'google.com' ] ).looping # 近端
#
# dig google.com @127.0.0.1 -p1717
#
module Girl
  class Resolv

    def initialize( port = 1717, nameservers = [], resolvd_host = nil, resolvd_port = nil, custom_domains = [] )
      resolv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resolv.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resolv.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "resolv bound on #{ port }"

      nameservers = nameservers.select{ | ns | Addrinfo.udp( ns, 53 ).ipv4? }

      if nameservers.empty?
        nameservers = %w[ 114.114.114.114 114.114.115.115 ]
      end

      if resolvd_host && resolvd_port
        resolvd_addr = Socket.sockaddr_in( resolvd_port, resolvd_host )
      end

      @pub_addrs = nameservers.map{ | ns | Socket.sockaddr_in( 53, ns ) }
      @resolv = resolv
      @resolvd_addr = resolvd_addr
      @custom_qnames = custom_domains.map{ |dom| dom.split( '.' ).map{ | sub | [ sub.size ].pack( 'C' ) + sub }.join }
      @ids = {}
      @caches = {}
      @hex = Girl::Hex.new
      @mutex = Mutex.new
    end

    def looping
      if @resolvd_addr
        loop_heartbeat
      end

      loop do
        rs, _ = IO.select( [ @resolv ] )

        rs.each do | sock |
          read_sock( sock )
        end
      end
    end

    def quit!
      exit
    end

    private

    def loop_heartbeat
      Thread.new do
        loop do
          sleep 59

          @mutex.synchronize do
            heartbeat = [ rand( 128 ) ].pack( 'C' )
            # puts "debug heartbeat #{ heartbeat.inspect } #{ Time.new }"
            @resolv.sendmsg( heartbeat, 0, @resolvd_addr )
          end
        end
      end
    end

    def read_sock( sock )
      # https://tools.ietf.org/html/rfc1035#page-26
      data, addrinfo, rflags, *controls = sock.recvmsg
      # puts "debug recvmsg #{ data.inspect }"
      src = addrinfo.to_sockaddr

      if src == @resolvd_addr
        data = @hex.decode( data )
      end

      if data.size <= 12
        puts "missing header? #{ Time.new }"
        return
      end

      id = data[ 0, 2 ]
      qr = data[ 2, 2 ].unpack( 'B16' ).first[ 0 ]
      qname_len = data[ 12..-1 ].index([ 0 ].pack( 'C' ))

      unless qname_len
        puts "missing qname? #{ Time.new }"
        return
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
            sock.sendmsg( cache, 0, src )
            return
          else
            @caches.delete( question )
          end
        end

        is_custom = @custom_qnames.any?{ | custom | qname.include?( custom ) }

        if is_custom
          data = @hex.encode( data )
          sock.sendmsg( data, 0, @resolvd_addr )
        else
          @pub_addrs.each do | pub_addr |
            sock.sendmsg( data, 0, pub_addr )
          end
        end

        @ids[ id ] = [ src, is_custom ]
      elsif qr == '1' && @ids.include?( id )
        # relay the fastest response, ignore followings
        src, is_custom = @ids.delete( id )
        ancount = data[ 6, 2 ].unpack( 'n' ).first
        nscount = data[ 8, 2 ].unpack( 'n' ).first
        qname = data[ 12, qname_len ]
        sock.sendmsg( data, 0, src )

        return if ancount == 0 && nscount == 0

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

        return if ttls.empty?

        # cache data and set expire by shortest TTL
        question = qname + data[ 12 + qname_len, 5 ]
        @caches[ question ] = [ data, *ttls.sort_by{ | _, exp | exp }.first ]
      end
    end

  end
end
