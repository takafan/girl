require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Resolvd - dns查询得到正确的ip。远端。
#
module Girl
  class Resolvd

    def initialize( port = 7070, nameservers = [] )
      resolvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resolvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resolvd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "resolvd bound on #{ port }"

      nameservers = nameservers.select{ | ns | Addrinfo.udp( ns, 53 ).ipv4? }

      @resolvd = resolvd
      @pub_addrs = nameservers.map{ | ns | Socket.sockaddr_in( 53, ns ) }
      @ids = {}
      @hex = Girl::Hex.new
    end

    def looping
      loop do
        rs, _ = IO.select( [ @resolvd ] )

        rs.each do | sock |
          read_sock( sock )
        end
      end
    end

    def quit!
      exit
    end

    def read_sock( sock )
      data, addrinfo, rflags, *controls = sock.recvmsg
      # puts "debug recvmsg #{ data.inspect }"

      if data.size <= 12
        # heartbeat
        return
      end

      src = addrinfo.to_sockaddr

      unless @pub_addrs.include?( src )
        data = @hex.decode( data )
      end

      id = data[ 0, 2 ]
      qr = data[ 2, 2 ].unpack( 'B16' ).first[ 0 ]
      qname_len = data[ 12..-1 ].index( [ 0 ].pack( 'C' ) )

      unless qname_len
        puts 'missing qname?'
        return
      end

      if qr == '0'
        qname = data[ 12, qname_len ]

        @pub_addrs.each do | pub_addr |
          sock.sendmsg( data, 0, pub_addr )
        end

        @ids[ id ] = src
      elsif qr == '1' && @ids.include?( id )
        # relay the fastest response, ignore followings
        src = @ids.delete( id )
        data = @hex.encode( data )
        sock.sendmsg( data, 0, src )
      end
    end

  end
end
