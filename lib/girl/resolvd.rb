require 'socket'

module Girl
  class Resolvd

    def initialize( port, nameservers = [] )
      sock = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      sock.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "Binding on #{ port }"

      if nameservers.empty?
        nameservers = %w[ 8.8.8.8 ]
      end

      pub_sockaddrs = nameservers.map{ |ip| Socket.sockaddr_in( 53, ip ) }
      ids = {}

      loop do
        IO.select( [ sock ] )

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
          pub_sockaddrs.each{ | sockaddr | sock.sendmsg( data, 0, sockaddr ) }
          ids[ id ] = sender
        elsif qr == '1' && ids.include?( id )
          # relay the fastest response, ignore followings
          src = ids.delete( id )
          qname = data[ 12, qname_len ]
          data[ 12, qname_len ] = swap( qname )
          sock.sendmsg( data, 0, src )
        end
      end
    end

    def swap( data )
      data
    end

  end
end
