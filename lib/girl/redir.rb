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
      @delays = []
      @writes = {} # sock => ''
      @roles = {} # :redir / :source / :relay
      @timestamps = {} # sock => r/w.timestamp
      @twins = {} # source <=> relay
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 128 )
      puts "p#{ Process.pid } listening on #{ redir_port }"

      @reads << redir
      @roles[ redir ] = :redir
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :redir
            now = Time.new
            print "p#{ Process.pid } #{ now } "

            @timestamps.select{ | so, stamp | ( [ :source, :relay ].include?( @roles[ so ] ) ) && ( now - stamp > 600 ) }.each do | so, _ |
              close_socket( so )
            end

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            rescue Errno::EMFILE => e
              puts e.class
              quit!
            end

            begin
              # SO_ORIGINAL_DST
              # https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
            rescue Exception => e
              puts "get SO_ORIGINAL_DST #{ e.class }"
              source.close
              next
            end

            dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
            relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

            begin
              relay.connect_nonblock( @relayd_sockaddr )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              puts "connect relayd #{ e.class }"
              relay.close
              next
            end

            @reads << source
            @roles[ source ] = :source
            @writes[ source ] = ''
            @timestamps[ source ] = now
            @twins[ source ] = relay

            @reads << relay
            @roles[ relay ] = :relay
            @writes[ relay ] = @hex.swap( @hex.mix( dst_host, dst_port ) )
            @timestamps[ relay ] = now
            @twins[ relay ] = source
          when :source
            relay = @twins[ sock ]

            if relay.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            @writes[ relay ] << @hex.swap( data )
            @timestamps[ relay ] = now

            if @writes[ relay ].size >= 4194304
              @delays << @reads.delete( sock )
            end
          when :relay
            source = @twins[ sock ]

            if source.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e  # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            @writes[ source ] << @hex.swap( data )
            @timestamps[ source ] = now

            if @writes[ source ].size >= 4194304
              @delays << @reads.delete( sock )
            end
          end
        end

        writable_socks.each do | sock |
          if sock.closed?
            next
          end

          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e # WaitReadable for SSL renegotiation
            next
          rescue Exception => e
            close_socket( sock )
            next
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          if @writes[ sock ].empty? && @delays.include?( sock )
            @reads << @delays.delete( sock )
          end
        end
      end
    end

    def quit!
      @writes.each{ | sock, _ | sock.close }
      @reads.clear
      @delays.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      exit
    end

    private

    def close_socket( sock )
      sock.close
      @reads.delete( sock )
      @delays.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
    end

  end
end
