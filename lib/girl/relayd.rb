require 'girl/xeh'
require 'socket'

module Girl
  class Relayd

    def initialize( port, xeh_block = nil )
      if xeh_block
        Girl::Xeh.class_eval( xeh_block )
      end

      @reads = []
      @writes = {} # sock => ''
      @roles = {} # :relayd / :relay / :dest
      @timestamps = {} # sock => r/w.timestamp
      @twins = {} # relay <=> dest
      @close_after_writes = {} # sock => exception
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

            @timestamps.select{ | so, stamp | ( @roles[ so ] == :relay ) && ( now - stamp > 600 ) }.each do | so, _ |
              deal_io_exception( so, EOFError.new, readable_socks, writable_socks )
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
            begin
              data = @xeh.swap( sock.read_nonblock( 4096 ) )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              check_timeout( sock, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            dest = @twins[ sock ]

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
              @reads << dest
              @roles[ dest ] = :dest
              @writes[ dest ] = ''
              @timestamps[ dest ] = now
              @twins[ dest ] = sock
              @twins[ sock ] = dest

              begin
                dest.connect_nonblock( Socket.sockaddr_in( dst_port, dst_host ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                deal_io_exception( dest, e, readable_socks, writable_socks )
                next
              end

              if data.empty?
                next
              end
            end

            @writes[ dest ] << data
            @timestamps[ dest ] = now
          when :dest
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
            @writes[ relay ] << @xeh.swap( data )
            @timestamps[ relay ] = now
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
      readable_socks.delete( sock )
      writable_socks.delete( sock )

      if twin
        if @writes[ twin ] && !@writes[ twin ].empty?
          @close_after_writes[ twin ] = e
        else
          close_socket( twin )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end
    end

    def close_socket( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
      @close_after_writes.delete( sock )
    end

  end
end
