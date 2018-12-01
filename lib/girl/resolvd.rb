require 'socket'

module Girl
  class Resolvd

    def initialize( port, nameservers = [] )
      pub_socks = {} # nameserver => sock
      pub_addrs = []
      pub_addr6s = []

      nameservers.each do | ip |
        addr = Socket.sockaddr_in( 53, ip )

        if Addrinfo.udp( ip, 53 ).ipv6?
          pub_addr6s << addr
        else
          pub_addrs << addr
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
      rescue Errno::EAFNOSUPPORT => e
        puts "AF_INET6 #{ e.class }"
      end

      @pub_socks = pub_socks
      @ids = {}
      @reconn = 0
    end

    def looping
      loop do
        readable_socks, _ = IO.select( @reads )
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

            @pub_socks.each do | sockaddr, alias_sock |
              begin
                alias_sock.sendmsg( data, 0, sockaddr )
                @reconn = 0
              rescue Errno::ENETUNREACH => e
                if @reconn > 100
                  raise e
                end

                sleep 5
                @reconn += 1
                puts "#{ e.class }, retry sendmsg to pub #{ @reconn }"
                retry
              end
            end

            @ids[ id ] = [ sender, sock ]
          elsif qr == '1' && @ids.include?( id )
            # relay the fastest response, ignore followings
            src, alias_sock = @ids.delete( id )
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

    def quit!
      @reads.each{ | sock | sock.close }
      exit
    end

  end
end
