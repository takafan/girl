require 'socket'

module Girl
  class Mirrord

    def initialize( roomd_port = 6060, appd_host = '127.0.0.1', tmp_dir = '/tmp/mirrord', room_timeout = 3600 )
      @reads = []
      @writes = {} # sock => ''
      @roles = {} # sock => # :roomd / :appd / :mirrd / :room / :app / :mirr
      @timestamps = {} # sock => last r/w
      @twins = {} # app <=> mirr
      @close_after_writes = {} # sock => exception
      @pending_apps = {} # app => appd
      @appd_infos = {} # appd => { room: room, mirrd: mirrd, pending_apps: { app: '' }, linked_apps: { app: mirr } }
      @appd_host = appd_host
      @tmp_dir = tmp_dir
      @room_timeout = room_timeout

      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 5 )
      puts "roomd listening on #{ roomd_port }"

      @reads << roomd
      @roles[ roomd ] = :roomd
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :roomd
            now = Time.new

            # clients' eof may dropped by its upper gateway.
            # so check timeouted rooms on server side too.
            @timestamps.select{ | so, stamp | ( @roles[ so ] == :room ) && ( now - stamp > @room_timeout ) }.each do | so, _ |
              close_socket( so )
            end

            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            @reads << room
            @roles[ room ] = :room
            @writes[ room ] = ''
            @timestamps[ room ] = now

            appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            appd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            appd.bind( Socket.pack_sockaddr_in( 0, @appd_host ) )
            appd.listen( 5 )
            puts "appd listening on #{ appd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"

            @reads << appd
            @roles[ appd ] = :appd

            mirrd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            mirrd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            mirrd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
            mirrd.listen( 5 )
            puts "mirrd listening on #{ mirrd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"

            @reads << mirrd
            @roles[ mirrd ] = :mirrd

            tmp_path = File.join( @tmp_dir, "#{ appd.local_address.ip_unpack.last }-#{ addr.ip_unpack.first }" )
            @appd_infos[ appd ] = {
              room: room,
              mirrd: mirrd,
              pending_apps: {},
              linked_apps: {},
              tmp_path: tmp_path
            }

            File.open( tmp_path, 'w' )
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            now = Time.new
            appd_info = @appd_infos[ sock ]
            room = appd_info[ :room ]
            mirrd = appd_info[ :mirrd ]

            @reads << app
            @roles[ app ] = :app
            @writes[ app ] = ''
            @timestamps[ app ] = now
            @pending_apps[ app ] = sock

            appd_info[ :pending_apps ][ app ] = ''
            @writes[ room ] << "#{ mirrd.local_address.ip_unpack.last };"
            @timestamps[ room ] = now
          when :mirrd
            begin
              mirr, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            _, appd_info = @appd_infos.find{ | _, info | info[ :mirrd ] == sock }
            app, buff = appd_info[ :pending_apps ].shift

            unless app
              puts "no more pending apps under appd?"
              next
            end

            @reads << mirr
            @roles[ mirr ] = :mirr
            @writes[ mirr ] = buff
            @timestamps[ mirr ] = Time.new

            @twins[ mirr ] = app
            @twins[ app ] = mirr
            appd_info[ :linked_apps ][ app ] = mirr
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            @timestamps[ sock ] = Time.new

            _, appd_info = @appd_infos.find{ | _, info| info[ :room ] == sock }

            if appd_info
              begin
                File.delete( appd_info[ :tmp_path ] )
              rescue Errno::ENOENT
              end

              tmp_path = "#{ appd_info[ :tmp_path ].split( '-' ).first }-#{ data }"

              begin
                File.open( tmp_path, 'w' )
              rescue Errno::ENOENT, ArgumentError => e
                puts "open tmp path #{ e.class }"
                close_socket( sock )
                next
              end

              appd_info[ :tmp_path ] = tmp_path
            end
          when :app
            mirr = @twins[ sock ]

            if mirr && mirr.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_socket( sock )
              @close_after_writes[ mirr ] = e
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            unless mirr
              appd = @pending_apps[ sock ]
              appd_info = @appd_infos[ appd ]
              appd_info[ :pending_apps ][ sock ] << data
              next
            end

            @writes[ mirr ] << data
            @timestamps[ mirr ] = now
          when :mirr
            app = @twins[ sock ]

            if app.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_socket( sock )
              @close_after_writes[ app ] = e
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            @writes[ app ] << data
            @timestamps[ app ] = now

            appd = @pending_apps[ app ]
            appd_info = @appd_infos[ appd ]
            @timestamps[ appd_info[ :room ] ] = now
          end
        end

        writable_socks.each do | sock |
          if sock.closed?
            next
          end

          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            next
          rescue Exception => e
            close_socket( sock )

            if @twins[ sock ]
              @close_after_writes[ @twins[ sock ] ] = e
            end

            next
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          if @writes[ sock ].empty? && @close_after_writes.include?( sock )
            unless @close_after_writes[ sock ].is_a?( EOFError )
              sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            end

            close_socket( sock )
          end
        end
      end
    end

    def quit!
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      @pending_apps.clear
      @appd_infos.clear
      @close_after_writes.clear
      exit
    end

    private

    def close_socket( sock )
      role = @roles[ sock ]

      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
      @close_after_writes.delete( sock )

      case role
      when :room
        appd, appd_info = @appd_infos.find{ | _, info | info[ :room ] == sock }

        if appd
          appd_port = appd.local_address.ip_unpack.last
          appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
          close_socket( appd )

          begin
            File.delete( appd_info[ :tmp_path ] )
          rescue Errno::ENOENT
          end

          mirrd = appd_info[ :mirrd ]
          mirrd_port = mirrd.local_address.ip_unpack.last
          mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
          close_socket( mirrd )

          appd_info[ :pending_apps ].each do | app, _ |
            app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( app )
            @pending_apps.delete( app )
          end

          appd_info[ :linked_apps ].each do | app, mirr |
            app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( app )
            @pending_apps.delete( app )
            mirr.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( mirr )
          end

          @appd_infos.delete( appd )
        end
      when :app
        appd = @pending_apps.delete( sock )
        appd_info = @appd_infos[ appd ]
        appd_info[ :pending_apps ].delete( sock )
        appd_info[ :linked_apps ].delete( sock )
      end
    end

  end
end
