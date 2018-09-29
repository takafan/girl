require 'socket'

module Girl
  class Resolvd

    def initialize( port, nameservers = [] )
      sock4 = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      sock4.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      sock4.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )

      sock6 = Socket.new( Socket::AF_INET6, Socket::SOCK_DGRAM, 0 )
      sock6.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      sock6.bind( Socket.sockaddr_in( port, '::0' ) )

      puts "Binding on #{ port }"

      pub_socks = {} # nameserver => sock
      ids = {}
      reconn = 0

      nameservers.each do | ip |
        pub_socks[ Socket.sockaddr_in( 53, ip ) ] = Addrinfo.udp( ip, 53 ).ipv6? ? sock6 : sock4
      end

      loop do
        readable_socks, _ = IO.select( [ sock4, sock6 ] )

        readable_socks.each do | sock |
          data, addrinfo, rflags, *controls = sock.recvmsg
          sender = addrinfo.to_sockaddr

          if data.size <= 12
            puts 'missing header?'
            next
          end

          id = data[ 0, 2 ]
          qr = data[ 2, 2 ].unpack( 'B16' ).first[ 0 ]
          qname_len = data[ 12..-1 ].index( [ 0 ].pack( 'C' ) )

          unless qname_len
            puts 'missing qname?'
            next
          end

          if qr == '0'
            qname = swap( data[ 12, qname_len ] )
            data[ 12, qname_len ] = qname

            pub_socks.each do | sockaddr, alias_sock |
              begin
                alias_sock.sendmsg( data, 0, sockaddr )
                reconn = 0
              rescue Errno::ENETUNREACH => e
                if reconn > 100
                  raise e
                end

                sleep 5
                reconn += 1
                puts "#{ e.class }, retry sendmsg to pub #{ reconn }"
                retry
              end
            end

            ids[ id ] = [ sender, sock ]
          elsif qr == '1' && ids.include?( id )
            # relay the fastest response, ignore followings
            src, alias_sock = ids.delete( id )
            qname = data[ 12, qname_len ]
            data[ 12, qname_len ] = swap( qname )
            alias_sock.sendmsg( data, 0, src )
          end
        end
      end
    end

    def swap( data )
      data
    end

  end
end
