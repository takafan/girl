##
# usage
# =====
#
# 1. Girl::Relayd.new( 8080 ).looping # @server
#
# 2. Girl::Redir.new( 1919, 'your.server.ip', 8080 ).looping # @home
#
# 3. dig www.google.com @127.0.0.1 -p1818 # dig with girl/resolv, got 216.58.217.196
#
# 4. iptables -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# 5. curl https://www.google.com/
#
require 'girl/hex'
require 'socket'

module Girl
  class Redir

    def initialize( redir_port, relayd_host, relayd_port, hex_block = nil )
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      @reads = []
      @writes = {} # sock => ''
      @roles = {} # :redir / :source / :relay
      @timestamps = {} # sock => push_to_reads_or_writes.timestamp
      @twins = {} # source <=> relay
      @close_after_writes = {} # sock => exception
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 128 )
      puts "p#{ Process.pid } listening on #{ redir_port }"

      @reads << redir
      @roles[ redir ] = :redir
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ |_, buff| !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :redir
            print "p#{ Process.pid } #{ Time.new } "

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            now = Time.new
            @reads << source
            @roles[ source ] = :source
            @writes[ source ] = ''
            @timestamps[ source ] = now

            begin
              # SO_ORIGINAL_DST
              # https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
            rescue Exception => e
              puts "get SO_ORIGINAL_DST #{ e.class }"
              close_socket( source )
              next
            end

            dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
            relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            @reads << relay
            @roles[ relay ] = :relay
            @twins[ relay ] = source
            @twins[ source ] = relay

            begin
              relay.connect_nonblock( @relayd_sockaddr )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              deal_io_exception( relay, e, readable_socks, writable_socks )
              next
            end

            @writes[ relay ] = @hex.swap( @hex.mix( dst_host, dst_port ) )
            @timestamps[ relay ] = now
          when :source
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              check_timeout( sock, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            relay = @twins[ sock ]
            @writes[ relay ] << @hex.swap( data )
            @timestamps[ relay ] = now
          when :relay
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e  # WaitWritable for SSL renegotiation
              check_timeout( sock, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            source = @twins[ sock ]
            @writes[ source ] << @hex.swap( data )
            @timestamps[ source ] = now
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e # WaitReadable for SSL renegotiation
            check_timeout( sock, e, readable_socks, writable_socks )
            next
          rescue Exception => e
            deal_io_exception( sock, e, readable_socks, writable_socks )
            next
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          unless @writes[ sock ].empty?
            next
          end

          e = @close_after_writes.delete( sock )

          if e
            sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
            close_socket( sock )
            next
          end
        end
      end
    end

    # quit! in Signal.trap :TERM
    def quit!
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      @close_after_writes.clear

      exit
    end

    private

    def check_timeout( sock, e, readable_socks, writable_socks )
      if Time.new - @timestamps[ sock ] >= 5
        puts "#{ @roles[ sock ] } #{ e.class } timeout"
        deal_io_exception( sock, e, readable_socks, writable_socks )
      end
    end

    def deal_io_exception( sock, e, readable_socks, writable_socks )
      twin = @twins[ sock ]
      close_socket( sock )

      if twin
        if @writes.include?( twin )
          @reads.delete( twin )
          @twins.delete( twin )
          @close_after_writes[ twin ] = e
        else
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
          close_socket( twin )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end

      writable_socks.delete( sock )
    end

    def close_socket( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
    end

  end
end
