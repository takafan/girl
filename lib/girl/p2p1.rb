require 'girl/usr'
require 'socket'

module Girl
  class P2p1

    def initialize( roomd_host, roomd_port, appd_host, appd_port, timeout = 1800, room_title = nil )
      @reads = []
      @writes = {} # sock => ''
      @roles = {}  # sock => :room / :p1 / :app
      @timestamps = {} # sock => push_to_reads_or_writes.timestamp
      @twins = {} # p1 <=> app
      @roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      @appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      @appd_host = appd_host
      @appd_port = appd_port
      @timeout = timeout
      @room_title = room_title
      @reconn = 0
      @usr = Girl::Usr.new

      connect_roomd
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ |_, buff| !buff.empty? }.keys, [], @timeout )

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
              check_timeout( sock, e )
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

            if @roles.find{ | _, role | role == :p1 }
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            p2_ip, p2_port = data.split( ':' )

            p1 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            p1.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

            begin
              p1.bind( sock.local_address ) # use the hole
            rescue Errno::EADDRINUSE => e
              puts "bind #{ e.class }, flash a room"
              connect_roomd
              break
            end

            @reads << p1
            @roles[ p1 ] = :p1
            @writes[ p1 ] = ''
            @timestamps[ p1 ] = now

            begin
              p1.connect_nonblock( Socket.sockaddr_in( p2_port, p2_ip ) )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              puts "p2p #{ p2_ip }:#{ p2_port } #{ e.class }, flash a room"
              connect_roomd
              break
            end
          when :p1
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( sock, e )
              next
            rescue Exception => e
              puts "r #{ @roles[ sock ] } #{ e.class }, flash a room"
              connect_roomd
              break
            end

            now = Time.new
            @timestamps[ sock ] = now
            app = @twins[ sock ]

            unless app
              app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              @reads << app
              @roles[ app ] = :app
              @writes[ app ] = ''
              @timestamps[ app ] = now
              @twins[ app ] = sock
              @twins[ sock ] = app

              begin
                app.connect_nonblock( @appd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "c appd #{ @appd_host }:#{ @appd_port } #{ e.class }, flash a room"
                connect_roomd
                break
              end

              if data[ 0 ] == '!' # here comes a new app!
                data = data[ 1..-1 ]
                if data.empty?
                  next
                end
              end
            end

            @writes[ app ] << @usr.swap( data )
            @timestamps[ app ] = now
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( sock, e )
              next
            rescue Exception => e
              puts "r #{ @roles[ sock ] } #{ e.class }, flash a room"
              connect_roomd
              break
            end

            now = Time.new
            @timestamps[ sock ] = now

            p1 = @twins[ sock ]
            @writes[ p1 ] << @usr.swap( data )
            @timestamps[ p1 ] = now
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            check_timeout( sock, e )
            next
          rescue Exception => e
            puts "w #{ @roles[ sock ] } #{ e.class }, flash a room"
            connect_roomd
            break
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          unless @writes[ sock ].empty?
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

      exit
    end

    private

    def check_timeout( sock, e )
      if Time.new - @timestamps[ sock ] >= 5
        puts "#{ @roles[ sock ] } #{ e.class } timeout"
        connect_roomd
      end
    end

    def connect_roomd
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        sock.connect_nonblock( @roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
        @reads << sock
        @roles[ sock ] = :room

        if @room_title
          @writes[ sock ] = "room#{ @room_title }".unpack( "C*" ).map{ |c| c.chr }.join
        end
      end
    end
  end
end
