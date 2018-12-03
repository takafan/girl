require 'nio'
require 'socket'

module Girl
  class Mirrord

    def initialize( roomd_port = 6060, appd_host = '127.0.0.1', tmp_dir = '/tmp/mirrord', timeout = 3600, chunk_dir = '/tmp/mirrord/cache', managed_sock = nil )
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/mirrord/{pid}-{object_id}.0, ... ] }
      @close_after_writes = []
      @appd_host = appd_host
      @tmp_dir = tmp_dir
      @chunk_dir = chunk_dir
      @selector = NIO::Selector.new
      @roles = {} # mon =>  :roomd / :appd / :mirrd / :room / :app / :mirr / :managed
      @timestamps = {} # mon => last r/w
      @twins = {} # app_mon <=> mirr_mon
      @appd_infos = {} # appd_mon => { room_mon: room_mon, mirrd_mon: mirrd_mon, pending_app_mons: { app_mon: '' }, linked_app_mons: { app_mon: mirr_mon } }
      @pending_app_mons = {} # app_mon => appd_mon
      @timeout = timeout

      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 5 )
      puts "roomd listening on #{ roomd_port }"
      roomd_mon = @selector.register( roomd, :r )
      @roles[ roomd_mon ] = :roomd

      if managed_sock
        puts "p#{ Process.pid } reg managed on #{ managed_sock.local_address.ip_unpack.last }"
        mon = @selector.register( managed_sock, :r )
        @roles[ mon ] = :managed
      end
    end

    def looping
      loop do
        @selector.select do | mon |
          sock = mon.io

          if mon.readable?
            case @roles[ mon ]
            when :roomd
              now = Time.new

              begin
                room, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              room.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
              @buffs[ room ] = ''
              @chunks[ room ] = { seed: 0, files: [] }
              room_mon = @selector.register( room, :r )
              @roles[ room_mon ] = :room
              @timestamps[ room_mon ] = now

              appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
              appd.bind( Socket.pack_sockaddr_in( 0, @appd_host ) )
              appd.listen( 5 )
              puts "appd listening on #{ appd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"
              appd_mon = @selector.register( appd, :r )
              @roles[ appd_mon ] = :appd
              @timestamps[ appd_mon ] = now

              mirrd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
              mirrd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
              mirrd.listen( 5 )
              puts "mirrd listening on #{ mirrd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"
              mirrd_mon = @selector.register( mirrd, :r )
              @roles[ mirrd_mon ] = :mirrd
              @timestamps[ mirrd_mon ] = now

              tmp_path = File.join( @tmp_dir, "#{ appd.local_address.ip_unpack.last }-#{ addr.ip_unpack.first }" )
              @appd_infos[ appd_mon ] = {
                room_mon: room_mon,
                mirrd_mon: mirrd_mon,
                pending_app_mons: {},
                linked_app_mons: {},
                tmp_path: tmp_path
              }
              File.open( tmp_path, 'w' )
            when :appd
              if sock.closed?
                next
              end

              begin
                app, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              @buffs[ app ] = ''
              @chunks[ app ] = { seed: 0, files: [] }
              app_mon = @selector.register( app, :r )
              @roles[ app_mon ] = :app
              @timestamps[ app_mon ] = Time.new
              @pending_app_mons[ app_mon ] = mon
              appd_info = @appd_infos[ mon ]
              appd_info[ :pending_app_mons ][ app_mon ] = ''
              room_mon = appd_info[ :room_mon ]
              mirrd_mon = appd_info[ :mirrd_mon ]
              buffer( room_mon, "#{ mirrd_mon.io.local_address.ip_unpack.last };" )
            when :mirrd
              if sock.closed?
                next
              end

              begin
                mirr, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              _, appd_info = @appd_infos.find{ | _, info | info[ :mirrd_mon ] == mon }
              app_mon, buff = appd_info[ :pending_app_mons ].shift

              unless app_mon
                puts "no more pending apps under appd?"
                next
              end

              @buffs[ mirr ] = buff
              @chunks[ mirr ] = { seed: 0, files: [] }
              mirr_mon = @selector.register( mirr, :r )
              @roles[ mirr_mon ] = :mirr
              @timestamps[ mirr_mon ] = Time.new
              @twins[ mirr_mon ] = app_mon
              @twins[ app_mon ] = mirr_mon
              appd_info[ :linked_app_mons ][ app_mon ] = mirr_mon
            when :room
              if sock.closed?
                next
              end

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_mon( mon )
                next
              end

              @timestamps[ mon ] = Time.new

              _, appd_info = @appd_infos.find{ | _, info| info[ :room_mon ] == mon }

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
                  close_mon( mon )
                  next
                end

                appd_info[ :tmp_path ] = tmp_path
              end
            when :app
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin && twin.io.closed?
                close_mon( mon )
                next
              end

              now = Time.new

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              @timestamps[ mon ] = now

              unless twin
                appd_mon = @pending_app_mons[ mon ]
                appd_info = @appd_infos[ appd_mon ]
                appd_info[ :pending_app_mons ][ mon ] << data
                @timestamps[ appd_mon ] = now
                @timestamps[ appd_info[ :room_mon ] ] = now
                @timestamps[ appd_info[ :mirrd_mon ] ] = now
                next
              end

              buffer( twin, data )
            when :mirr
              if sock.closed?
                next
              end

              twin = @twins[ mon ]
              appd_mon = @pending_app_mons[ twin ]

              if twin.io.closed? || appd_mon.nil?
                close_mon( mon )
                next
              end

              now = Time.new

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              appd_info = @appd_infos[ appd_mon ]
              @timestamps[ mon ] = now
              @timestamps[ appd_mon ] = now
              @timestamps[ appd_info[ :room_mon ] ] = now
              @timestamps[ appd_info[ :mirrd_mon ] ] = now

              buffer( twin, data )
            when :managed
              data, addrinfo, rflags, *controls = sock.recvmsg
              data = data.strip

              if data == 't'
                now = Time.new
                puts "p#{ Process.pid } check timeout #{ now }"

                @timestamps.select{ | _, stamp | now - stamp > @timeout }.each do | mo, _ |
                  close_mon( mo )
                end
              else
                puts "unknown manage code"
              end
            end
          end

          if mon.writable?
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
              close_by_exception( mon, e )
              next
            end

            @timestamps[ mon ] = Time.new
            data = data[ written..-1 ]

            if @writes[ sock ] == :buff
              @buffs[ sock ] = data

              if data.empty?
                complete_write( mon )
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
                    complete_write( mon )
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
    end

    def quit!
      @roles.each{ | mon, _ | mon.io.close }
      @chunks.each do | sock, chunk |
        chunk[ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      exit
    end

    private

    def buffer( mon, data )
      sock = mon.io
      @buffs[ sock ] << data

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

      mon.add_interest( :w )
    end

    def complete_write( mon )
      sock = mon.io

      @writes.delete( sock )
      mon.remove_interest( :w )

      if @close_after_writes.include?( sock )
        close_mon( mon )
      end
    end

    def close_by_exception( mon, e )
      twin = @twins[ mon ]
      close_mon( mon )

      if twin
        twin_sock = twin.io

        unless twin_sock.closed?
          unless e.is_a?( EOFError )
            twin_sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
          end

          if @writes.include?( twin_sock )
            @close_after_writes << twin_sock
          else
            close_mon( twin )
          end
        end
      end
    end

    def close_mon( mon )
      sock = mon.io
      sock.close

      if @chunks[ sock ]
        @chunks[ sock ][ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      @writes.delete( sock )
      @buffs.delete( sock )
      @caches.delete( sock )
      @chunks.delete( sock )
      @close_after_writes.delete( sock )
      @selector.deregister( sock )
      @roles.delete( mon )
      @timestamps.delete( mon )
      @twins.delete( mon )
      @pending_app_mons.delete( mon )
      info = @appd_infos.delete( mon )

      if info
        begin
          File.delete( info[ :tmp_path ] )
        rescue Errno::ENOENT
        end
      end
    end

  end
end
