require 'nio'
require 'socket'

module Girl
  class P2p1

    def initialize( roomd_host, roomd_port, appd_host, appd_port, timeout = 1800, room_title = nil )
      @writes = {} # sock => ''
      @roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      @appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      @appd_host = appd_host
      @appd_port = appd_port
      @room_title = room_title
      @selector = NIO::Selector.new
      @roles = {}  # mon => :room / :p1 / :app
      @timestamps = {} # mon => last r/w
      @twins = {} # p1_mon <=> app_mon
      @swaps = {} # p1_mon => nil or length
      @swaps2 = [] # p1_mons
      @timeout = timeout

      connect_roomd
    end

    def looping
      loop do
        @selector.select do | mon |
          sock = mon.io

          if mon.readable?
            case @roles[ mon ]
            when :room
              now = Time.new

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ETIMEDOUT => e
                puts "#{ now } read #{ @roles[ mon ] } #{ e.class }"

                if [ EOFError, Errno::ECONNREFUSED ].include?( e.class )
                  connect_roomd
                else
                  sock.close
                end

                break
              end

              if @roles.find{ | _, role | role == :p1 }
                puts 'already paired, ignore'
                next
              end

              @timestamps[ mon ] = now
              p2_ip, p2_port = data.split( ':' )

              p1 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              p1.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

              begin
                p1.bind( sock.local_address ) # use the hole
              rescue Errno::EADDRINUSE => e
                puts "bind #{ e.class }"
                connect_roomd
                break
              end

              begin
                p1.connect_nonblock( Socket.sockaddr_in( p2_port, p2_ip ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "p2p #{ p2_ip }:#{ p2_port } #{ e.class }"
                connect_roomd
                break
              end

              @writes[ p1 ] = ''
              p1_mon = @selector.register( p1, :r )
              @roles[ p1_mon ] = :p1
              @timestamps[ p1_mon ] = now
              @swaps[ p1_mon ] = nil
              @swaps2 << p1_mon
            when :p1
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin && twin.io.closed?
                connect_roomd
                break
              end

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                puts "read #{ @roles[ mon ] } #{ e.class }"
                connect_roomd
                break
              end

              now = Time.new
              @timestamps[ mon ] = now

              unless twin
                app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

                begin
                  app.connect_nonblock( @appd_sockaddr )
                rescue IO::WaitWritable, Errno::EINTR
                rescue Exception => e
                  puts "connect appd #{ @appd_host }:#{ @appd_port } #{ e.class }"
                  connect_roomd
                  break
                end

                @writes[ app ] = ''
                twin = @selector.register( app, :r )
                @roles[ twin ] = :app
                @timestamps[ twin ] = now
                @twins[ twin ] = mon
                @twins[ mon ] = twin

                if data[ 0 ] == '!' # here comes a new app!
                  data = data[ 1..-1 ]

                  if data.empty?
                    next
                  end
                end
              end

              if @swaps.include?( mon )
                len = @swaps[ mon ]

                unless len
                  if data.size < 2
                    puts "lonely char? #{ data.inspect }"
                    sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                    connect_roomd
                    break
                  end

                  len = data[ 0, 2 ].unpack( 'n' ).first
                  data = data[ 2..-1 ]
                end

                if data.size >= len
                  data = "#{ swap( data[ 0, len ] ) }#{ data[ len..-1 ] }"
                  @swaps.delete( mon )
                else
                  data = swap( data )
                  @swaps[ mon ] = len - data.size
                end
              end

              buffer( twin, data )
            when :app
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin.io.closed?
                connect_roomd
                break
              end

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                puts "read #{ @roles[ mon ] } #{ e.class }"
                connect_roomd
                break
              end

              @timestamps[ mon ] = Time.new

              if @swaps2.delete( twin )
                data = "#{ [ data.size ].pack( 'n' ) }#{ swap( data ) }"
              end

              buffer( twin, data )
            end
          end

          if mon.writable?
            if sock.closed?
              next
            end

            data = @writes[ sock ]

            begin
              written = sock.write_nonblock( data )
            rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
              next
            rescue Exception => e
              puts "write #{ @roles[ mon ] } #{ e.class }"
              connect_roomd
              break
            end

            @timestamps[ mon ] = Time.new
            @writes[ sock ] = data[ written..-1 ]

            unless @writes[ sock ].empty?
              next
            end

            mon.remove_interest( :w )
          end
        end
      end
    end

    def quit!
      @roles.each{ | mon, _ | mon.io.close }
      exit
    end

    private

    def buffer( mon, data )
      @writes[ mon.io ] << data
      mon.add_interest( :w )
    end

    def connect_roomd
      @roles.each do | mon, _ |
        sock = mon.io
        sock.close
        @selector.deregister( sock )
        @roles.delete( mon )
      end

      @writes.clear
      @timestamps.clear
      @twins.clear
      @swaps.clear
      @swaps2.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        sock.connect_nonblock( @roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
      rescue Errno::ENETUNREACH => e
        puts "#{ Time.new } connect roomd #{ e.class }"
        sock.close
        return
      end

      @writes[ sock ] = ''
      mon = @selector.register( sock, :r )
      @roles[ mon ] = :room
      @timestamps[ mon ] = Time.new

      if @room_title
        buffer( mon, "room#{ @room_title }".unpack( "C*" ).map{ | c | c.chr }.join )
      end
    end

    def swap( data )
      data
    end

  end
end
