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
      timestamps = {} # sock => push_to_reads_or_writes.timestamp
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
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            now = Time.new
            reads[ source ] = :source
            buffs[ source ] = ''
            timestamps[ source ] = now

            begin
              # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              # http://man7.org/linux/man-pages/man2/getsockopt.2.html
              dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
            rescue Exception => e
              puts "get SO_ORIGINAL_DST #{ e.class }"
              close_socket( source, reads, buffs, writes, timestamps, twins )
              next
            end

            dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
            relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            reads[ relay ] = :relay
            twins[ relay ] = source
            twins[ source ] = relay

            begin
              relay.connect_nonblock( relayd_sockaddr )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              deal_io_exception( relay, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            buffs[ relay ] = hex.swap( hex.mix( dst_host, dst_port ) )
            writes[ relay ] = :relay
            timestamps[ relay ] = now
          when :source
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            relay = twins[ sock ]
            buffs[ relay ] << hex.swap( data )
            writes[ relay ] = :relay
            timestamps[ relay ] = now
          when :relay
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e  # WaitWritable for SSL renegotiation
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            source = twins[ sock ]
            buffs[ source ] << hex.swap( data )
            writes[ source ] = :source
            timestamps[ source ] = now
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( buffs[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e # WaitReadable for SSL renegotiation
            check_timeout( 'w', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
            next
          rescue Exception => e
            deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
            next
          end

          timestamps[ sock ] = Time.new
          buffs[ sock ] = buffs[ sock ][ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          e = close_after_writes.delete( sock )

          if e
            sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
            close_socket( sock, reads, buffs, writes, timestamps, twins )
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def check_timeout( mode, sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      if Time.new - timestamps[ sock ] >= 5
        puts "#{ mode == 'r' ? reads[ sock ] : writes[ sock ] } #{ mode } #{ e.class } timeout"
        deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      end
    end

    def deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      twin = close_socket( sock, reads, buffs, writes, timestamps, twins )

      if twin
        if writes.include?( twin )
          reads.delete( twin )
          twins.delete( twin )
          close_after_writes[ twin ] = e
        else
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
          close_socket( twin, reads, buffs, writes, timestamps, twins )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end

      writable_socks.delete( sock )
    end

    def close_socket( sock, reads, buffs, writes, timestamps, twins )
      sock.close
      reads.delete( sock )
      buffs.delete( sock )
      writes.delete( sock )
      timestamps.delete( sock )
      twins.delete( sock )
    end

  end
end
