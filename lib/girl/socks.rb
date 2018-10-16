##
# usage
# =====
#
# Girl::Socks.new( '127.0.0.1', 1080, '127.0.0.1', 1818, 'your.server.ip', 8080 )
#
# ALL_PROXY=socks5://127.0.0.1:1080 git pull
#
require 'socket'
require 'resolv'

module Girl
  class Socks

    def initialize( socks_host, socks_port, resolv_host, resolv_port, relayd_host, relayd_port )
      hex = Girl::Hex.new
      socks5 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      socks5.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      socks5.bind( Socket.pack_sockaddr_in( socks_port, socks_host ) )
      socks5.listen( 128 )

      puts "p#{ Process.pid } listening on #{ socks_host }:#{ socks_port }"

      reads = {
        socks5 => :socks5 # :socks5 / :source / :relay
      }
      procs = {} # source => :connect / :request / :passing
      buffs = {} # sock => ''
      writes = {}  # sock => :source / :relay
      twins = {} # source <=> relay
      close_after_writes = {} # sock => exception
      dns = Resolv::DNS.new( nameserver_port: [ [ resolv_host, resolv_port ] ] )
      relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys )

        readable_socks.each do | sock |
          case reads[ sock ]
          when :socks5
            print "p#{ Process.pid } #{ Time.new } "

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              print ' a'
              next
            end

            reads[ source ] = :source
            buffs[ source ] = ''
            procs[ source ] = :connect
          when :source
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            if procs[ sock ] == :connect
              ver = data[ 0 ].unpack( 'C' ).first
              if ver != 5
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock, reads, buffs, writes, twins )
                next
              end

              buffs[ sock ] << [ 5, 0 ].pack( 'C2' )
              writes[ sock ] = :source
              procs[ sock ] = :request
            elsif procs[ sock ] == :request

              # +----+-----+-------+------+----------+----------+
              # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
              # +----+-----+-------+------+----------+----------+
              # | 1  |  1  | X'00' |  1   | Variable |    2     |
              # +----+-----+-------+------+----------+----------+

              atyp = data[ 3 ].unpack( 'C' ).first

              case atyp
              when 1
                dst_addr = data[ 4, 4 ]
                dst_host = dst_addr.unpack( 'N' ).first
                dst_port = data[ 8, 2 ].unpack( 'n' ).first
              when 3
                len = data[ 4 ].unpack( 'C' ).first
                domain_name = data[ 5, len ]
                dst_port = data[ 5 + len, 2 ].unpack( 'n' ).first
                ip = dns.getaddress( domain_name ).to_s
                dst_addr = Socket.sockaddr_in( dst_port, ip )
                _, dst_port, dst_host = dst_addr.unpack( 'nnN' )
              else
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock, reads, buffs, writes, twins )
                next
              end

              relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              reads[ relay ] = :relay
              buffs[ relay ] = hex.swap( hex.mix( dst_host, dst_port ) )
              writes[ relay ] = :relay
              twins[ relay ] = sock
              twins[ sock ] = relay

              begin
                relay.connect_nonblock( relayd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                deal_io_exception( relay, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
                next
              end

              # +----+-----+-------+------+----------+----------+
              # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
              # +----+-----+-------+------+----------+----------+
              # | 1  |  1  | X'00' |  1   | Variable |    2     |
              # +----+-----+-------+------+----------+----------+

              _, sock_port, sock_host = sock.getsockname.unpack( 'nnN' )
              buffs[ sock ] << [ 5, 0, 0, 1, sock_host, sock_port ].pack( 'C4Nn' )
              writes[ sock ] = :source
              procs[ sock ] = :passing
            elsif procs[ sock ] == :passing
              relay = twins[ sock ]
              buffs[ relay ] << hex.swap( data )
              writes[ relay ] = :relay
            end
          when :relay
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            source = twins[ sock ]
            buffs[ source ] << hex.swap( data )
            writes[ source ] = :source
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable
            next
          rescue Exception => e
            deal_io_exception( sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
            next
          end

          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          e = close_after_writes.delete( sock )

          if e
            sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
            close_socket( sock, reads, buffs, writes, twins )
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def deal_io_exception( sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
      twin = close_socket( sock, reads, buffs, writes, twins )

      if twin
        if writes.include?( twin )
          reads.delete( twin )
          twins.delete( twin )
          close_after_writes[ twin ] = e
        else
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack( 'ii' ) ) unless e.is_a?( EOFError )
          close_socket( twin, reads, buffs, writes, twins )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end

      writable_socks.delete( sock )
    end

    def close_socket( sock, reads, buffs, writes, twins )
      sock.close
      reads.delete( sock )
      buffs.delete( sock )
      writes.delete( sock )
      twins.delete( sock )
    end

  end
end
