##
# usage
# =====
#
# 1. Girl::Mirrord.new( 6060, '127.0.0.1' ).looping # @server
#
# 2. Girl::Mirror.new( '{ your.server.ip }', 6060, '127.0.0.1', 22, 1800, '周立波' ).looping # @home
#
# 3. ls -lt /tmp/mirrord # @server, saw 45678-周立波
#
# 4. ssh -p45678 libo@127.0.0.1
#
require 'socket'

module Girl
  class Mirror

    def initialize( roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22, timeout = 1800, room_title = nil )
      @reads = []
      @writes = {} # sock => ''
      @roles = {}  # sock => :room / :mirr / :app
      @timestamps = {} # sock => r/w.timestamp
      @twins = {} # mirr <=> app
      @close_after_writes = {} # sock => exception
      @roomd_host = roomd_host
      @roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      @room_title = room_title
      @appd_host = appd_host
      @appd_port = appd_port
      @appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      @timeout = timeout
      @reconn = 0

      connect_roomd
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys, [], @timeout )

        unless readable_socks
          puts "flash #{ Time.new }"
          connect_roomd
          next
        end

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
              @reconn = 0
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              if Time.new - @timestamps[ sock ] >= 5
                puts "room r #{ e.class } timeout"
                connect_roomd
              end

              next
            rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ETIMEDOUT => e
              if e.is_a?( EOFError )
                @reconn = 0
              elsif @reconn > 100
                raise e
              else
                @reconn += 1
              end

              sleep 5
              puts "#{ e.class }, reconn #{ @reconn }"
              connect_roomd
              break
            end

            now = Time.new
            @timestamps[ sock ] = now

            data.split( ';' ).map{ | s | s.to_i }.each do | mirrd_port |
              mirr = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

              @reads << mirr
              @roles[ mirr ] = :mirr
              @writes[ mirr ] = ''
              @timestamps[ mirr ] = now
              @twins[ mirr ] = app

              @reads << app
              @roles[ app ] = :app
              @writes[ app ] = ''
              @timestamps[ app ] = now
              @twins[ app ] = mirr

              begin
                mirr.connect_nonblock( Socket.sockaddr_in( mirrd_port, @roomd_host ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect mirrd #{ @roomd_host }:#{ mirrd_port } #{ e.class }"
                deal_io_exception( mirr, e, readable_socks, writable_socks )
                next
              end

              begin
                app.connect_nonblock( @appd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect appd #{ @appd_host }:#{ @appd_port } #{ e.class }"
                deal_io_exception( app, e, readable_socks, writable_socks )
                next
              end
            end
          when :mirr
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( sock, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            app = @twins[ sock ]
            @writes[ app ] << data
            @timestamps[ app ] = now
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( sock, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            mirr = @twins[ sock ]
            @writes[ mirr ] << data
            @timestamps[ mirr ] = now
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
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

    def connect_roomd
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      @close_after_writes.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

      begin
        sock.connect_nonblock( @roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
        @reads << sock
        @roles[ sock ] = :room

        if @room_title
          @writes[ sock ] = @room_title.unpack( "C*" ).map{ | c | c.chr }.join
        end
      end
    end

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
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
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
