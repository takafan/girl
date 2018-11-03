require 'girl/xeh'
require 'socket'

module Girl
  class Relayd

    def initialize( port, xeh_block = nil )
      if xeh_block
        Girl::Xeh.class_eval( xeh_block )
      end

      @reads = []
      @delays = []
      @writes = {} # sock => ''
      @roles = {} # :relayd / :relay / :dest
      @timestamps = {} # sock => r/w.timestamp
      @twins = {} # relay <=> dest
      @addrs = {} # sock => addrinfo
      @xeh = Girl::Xeh.new

      relayd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relayd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relayd.bind( Socket.pack_sockaddr_in( port, '0.0.0.0' ) )
      relayd.listen( 128 ) # cat /proc/sys/net/ipv4/tcp_max_syn_backlog
      puts "p#{ Process.pid } listening on #{ port }"

      @reads << relayd
      @roles[ relayd ] = :relayd
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :relayd
            now = Time.new
            print "p#{ Process.pid } #{ now } "

            @timestamps.select{ | so, stamp | ( [ :relay, :dest ].include?( @roles[ so ] ) ) && ( now - stamp > 600 ) }.each do | so, _ |
              close_socket( so )
            end

            begin
              relay, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            rescue Errno::EMFILE => e
              puts e.class
              quit!
            end

            @reads << relay
            @roles[ relay ] = :relay
            @writes[ relay ] = ''
            @timestamps[ relay ] = now
            @addrs[ relay ] = addr
          when :relay
            dest = @twins[ sock ]

            if dest && dest.closed?
              close_socket( sock )
              next
            end

            begin
              data = @xeh.swap( sock.read_nonblock( 4096 ) )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            unless dest
              ret = @xeh.decode( data, @addrs.delete( sock ) )

              unless ret[ :success ]
                puts ret[ :error ]
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock )
                next
              end

              data, dst_host, dst_port = ret[ :data ]
              dest = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              dest.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

              begin
                dest.connect_nonblock( Socket.sockaddr_in( dst_port, dst_host ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "connect destination #{ e.class }"
                dest.close
                next
              end

              @reads << dest
              @roles[ dest ] = :dest
              @writes[ dest ] = ''
              @timestamps[ dest ] = now
              @twins[ dest ] = sock
              @twins[ sock ] = dest

              if data.empty?
                next
              end
            end

            @writes[ dest ] << data
            @timestamps[ dest ] = now

            if @writes[ dest ].size >= 4194304
              @delays << @reads.delete( sock )
            end
          when :dest
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
            @writes[ relay ] << @xeh.swap( data )
            @timestamps[ relay ] = now

            if @writes[ relay ].size >= 4194304
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
