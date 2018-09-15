require 'girl/hex'
require 'socket'

module Girl
  class Redir

    def initialize( redir_port, relayd_host, relayd_port, hex_block = nil )
      Girl::Hex.class_eval( hex_block ) if hex_block
      hex = Girl::Hex.new
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 128 )

      puts "p#{ Process.pid } listening on #{ redir_port }"

      reads = {
        redir => :redir # :redir / :source / :relay
      }
      buffs = {} # sock => ''
      writes = {}  # sock => :source / :relay
      twins = {} # source <=> relay
      close_after_writes = {} # sock => exception
      relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys )

        readable_socks.each do | sock |
          case reads[ sock ]
          when :redir
            print "p#{ Process.pid } #{ Time.new } "

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              next
            end

            reads[ source ] = :source
            buffs[ source ] = ''

            begin
              # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              # http://man7.org/linux/man-pages/man2/getsockopt.2.html
              dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
            rescue Exception => e
              puts "get SO_ORIGINAL_DST #{ e.class }"
              close_socket( source, reads, buffs, writes, twins )
              next
            end

            dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
            relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            reads[ relay ] = :relay
            buffs[ relay ] = hex.swap( hex.mix( dst_host, dst_port ) )
            writes[ relay ] = :relay
            twins[ relay ] = source
            twins[ source ] = relay

            begin
              relay.connect_nonblock( relayd_sockaddr )
            rescue IO::WaitWritable
            rescue Exception => e
              deal_io_exception( relay, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end
          when :source
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            relay = twins[ sock ]
            buffs[ relay ] << hex.swap( data )
            writes[ relay ] = :relay
          when :relay
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable
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
          rescue IO::WaitWritable
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
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
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
