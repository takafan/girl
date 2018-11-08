require 'socket'

module Girl
  class Mirrord

    def initialize( roomd_port = 6060, appd_host = '127.0.0.1', tmp_dir = '/tmp/mirrord', room_timeout = 3600, chunk_dir = '/tmp/mirrord/cache' )
      @reads = []
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/mirrord/{pid}-{object_id}.0, ... ] }
      @roles = {} # sock => # :roomd / :appd / :mirrd / :room / :app / :mirr
      @timestamps = {} # sock => last r/w
      @twins = {} # app <=> mirr
      @close_after_writes = []
      @pending_apps = {} # app => appd
      @appd_infos = {} # appd => { room: room, mirrd: mirrd, pending_apps: { app: '' }, linked_apps: { app: mirr } }
      @appd_host = appd_host
      @tmp_dir = tmp_dir
      @room_timeout = room_timeout
      @chunk_dir = chunk_dir

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
        readable_socks, writable_socks = IO.select( @reads, @writes.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :roomd
            now = Time.new

            # clients' eof may dropped by its upper gateway.
            # so check timeouted rooms on server side too.
            @timestamps.each do | so, stamp |
              if @roles[ so ] == :room
                if now - stamp > @room_timeout
                  close_socket( so )
                end
              else
                if now - stamp > 86400
                  close_socket( so )
                end
              end
            end

            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            @reads << room
            @roles[ room ] = :room
            @buffs[ room ] = ''
            @chunks[ room ] = { seed: 0, files: [] }
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
            @buffs[ app ] = ''
            @chunks[ app ] = { seed: 0, files: [] }
            @timestamps[ app ] = now
            @pending_apps[ app ] = sock

            appd_info[ :pending_apps ][ app ] = ''
            buffer( room, "#{ mirrd.local_address.ip_unpack.last };" )
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
            @buffs[ mirr ] = buff
            @chunks[ mirr ] = { seed: 0, files: [] }
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
            if sock.closed?
              next
            end

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
              close_by_exception( sock, e )
              next
            end

            @timestamps[ sock ] = Time.new

            unless mirr
              appd = @pending_apps[ sock ]
              appd_info = @appd_infos[ appd ]
              appd_info[ :pending_apps ][ sock ] << data
              next
            end

            buffer( mirr, data )
          when :mirr
            if sock.closed?
              next
            end

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
              close_by_exception( sock, e )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now
            buffer( app, data )

            appd = @pending_apps[ app ]
            appd_info = @appd_infos[ appd ]
            @timestamps[ appd_info[ :room ] ] = now
          end
        end

        writable_socks.each do | sock |
          if sock.closed?
            next
          end

          if @writes[ sock ] == :buff
            data = @buffs[ sock ]
          else
            unless @caches[ sock ]
              @caches[ sock ] = IO.binread( @chunks[ sock ][ :files ][ 0 ] )
            end

            data = @caches[ sock ]
          end

          begin
            written = sock.write_nonblock( data )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e # WaitReadable for SSL renegotiation
            next
          rescue Exception => e
            close_by_exception( sock, e )
            next
          end

          @timestamps[ sock ] = Time.new
          data = data[ written..-1 ]

          if @writes[ sock ] == :buff
            @buffs[ sock ] = data

            if data.empty?
              complete_write( sock )
            end
          else
            if data.empty?
              @caches.delete( sock )

              begin
                File.delete( @chunks[ sock ][ :files ].shift )
              rescue Errno::ENOENT
              end

              if @chunks[ sock ][ :files ].empty?
                if @buffs[ sock ].empty?
                  complete_write( sock )
                else
                  @writes[ sock ] = :buff
                end
              end
            else
              @caches[ sock ] = data
            end
          end
        end
      end
    end

    def quit!
      @reads.each{ | sock | sock.close }
      @chunks.each do | sock, chunk |
        chunk[ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      @reads.clear
      @writes.clear
      @buffs.clear
      @caches.clear
      @chunks.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      @close_after_writes.clear
      @pending_apps.clear
      @appd_infos.clear

      exit
    end

    private

    def buffer( sock, data )
      @buffs[ sock ] << data
      @timestamps[ sock ] = Time.new

      if @writes[ sock ].nil?
        @writes[ sock ] = :buff
      elsif @buffs[ sock ].size >= 4194304
        chunk_path = File.join( @chunk_dir, "#{ Process.pid }-#{ sock.object_id }.#{ @chunks[ sock ][ :seed ] }" )
        IO.binwrite( chunk_path, @buffs[ sock ] )
        @chunks[ sock ][ :files ] << chunk_path
        @chunks[ sock ][ :seed ] += 1
        @writes[ sock ] = :cache
        @buffs[ sock ] = ''
      end
    end

    def complete_write( sock )
      @writes.delete( sock )

      if @close_after_writes.include?( sock )
        close_socket( sock )
      end
    end

    def close_by_exception( sock, e )
      twin = @twins[ sock ]
      close_socket( sock )

      if twin && !twin.closed?
        unless e.is_a?( EOFError )
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        end

        if @writes.include?( twin )
          @close_after_writes << twin
        else
          close_socket( twin )
        end
      end
    end

    def close_socket( sock )
      role = @roles[ sock ]
      sock.close

      if @chunks[ sock ]
        @chunks[ sock ][ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      @reads.delete( sock )
      @writes.delete( sock )
      @buffs.delete( sock )
      @caches.delete( sock )
      @chunks.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
      @close_after_writes.delete( sock )

      case role
      when :room
        appd, appd_info = @appd_infos.find{ | _, info | info[ :room ] == sock }
        mirrd = appd_info[ :mirrd ]

        begin
          File.delete( appd_info[ :tmp_path ] )
        rescue Errno::ENOENT
        end

        appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        close_socket( appd )

        mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        close_socket( mirrd )

        @appd_infos.delete( appd )
      when :app
        appd = @pending_apps.delete( sock )
        appd_info = @appd_infos[ appd ]
        if appd_info
          appd_info[ :pending_apps ].delete( sock )
          appd_info[ :linked_apps ].delete( sock )
        end
      end
    end

  end
end
