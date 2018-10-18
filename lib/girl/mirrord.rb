require 'socket'

module Girl
  class Mirrord

    def initialize( roomd_port = 6060, appd_host = '127.0.0.1', tmp_dir = '/tmp/mirrord', room_timeout = 3600 )
      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 ) # avoid EADDRINUSE after a restart
      roomd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 5 )
      puts "roomd listening on #{ roomd_port }"
      Dir.mkdir( tmp_dir ) unless Dir.exist?( tmp_dir )

      reads = {
        roomd => :roomd # :roomd / :appd / :mirrd / :room / :app / :mirr
      }
      buffs = {} # sock => ''
      writes = {} # sock => :room / :app / :mirr
      timestamps = {} # sock => push_to_reads_or_writes.timestamp
      twins = {} # app <=> mirr
      close_after_writes = {} # sock => exception
      pending_apps = {} # app => appd
      appd_infos = {} # appd => { room: room, mirrd: mirrd, pending_apps: { app: '' }, linked_apps: { app: mirr } }
      roomstamps = {} # room => room.last_mirr_read.timestamp

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys )

        readable_socks.each do | sock |
          case reads[ sock ]
          when :roomd
            now = Time.new

            # clients' eof may dropped by its upper gateway.
            # so check timeouted rooms on server side too.
            roomstamps.select{ | _, roomstamp | now - roomstamp > room_timeout }.each do | room, _ |
              deal_io_exception( reads[ room ], room, reads, buffs, writes, timestamps, twins, close_after_writes, EOFError.new, readable_socks, writable_socks, pending_apps, appd_infos )
              roomstamps.delete( room )
            end

            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            reads[ room ] = :room
            buffs[ room ] = ''
            timestamps[ room ] = now

            appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            appd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            appd.bind( Socket.pack_sockaddr_in( 0, appd_host ) )
            appd.listen( 5 )
            puts "appd listening on #{ appd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"

            reads[ appd ] = :appd

            mirrd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            mirrd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            mirrd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
            mirrd.listen( 5 )
            puts "mirrd listening on #{ mirrd.local_address.ip_unpack.join( ':' ) } of room #{ room.local_address.ip_unpack.join( ':' ) }"

            reads[mirrd] = :mirrd

            tmp_path = File.join( tmp_dir, "#{ appd.local_address.ip_unpack.last }-#{ addr.ip_unpack.first }" )
            appd_infos[ appd ] = {
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
            appd_info = appd_infos[ sock ]
            room = appd_info[ :room ]
            mirrd = appd_info[ :mirrd ]

            reads[ app ] = :app
            buffs[ app ] = ''
            timestamps[ app ] = now
            pending_apps[ app ] = sock

            appd_info[ :pending_apps ][ app ] = ''
            buffs[ room ] = "#{ mirrd.local_address.ip_unpack.last };"
            writes[ room ] = :room
            timestamps[ room ] = now
          when :mirrd
            begin
              mirr, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            _, appd_info = appd_infos.find{ |_, info| info[ :mirrd ] == sock }
            app, buff = appd_info[ :pending_apps ].shift

            unless app
              puts "no more pending apps under appd?"
              next
            end

            reads[ mirr ] = :mirr
            buffs[ mirr ] = buff
            timestamps[ mirr ] = Time.new
            writes[ mirr ] = :mirr unless buff.empty?

            twins[ mirr ] = app
            twins[ app ] = mirr
            appd_info[ :linked_apps ][ app ] = mirr
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            rescue Exception => e
              deal_io_exception( reads[ sock ], sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            end

            timestamps[ sock ] = Time.new

            _, appd_info = appd_infos.find{ | _, info| info[ :room ] == sock }

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
                deal_io_exception( reads[ sock ], sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
                next
              end

              appd_info[ :tmp_path ] = tmp_path
            end
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            rescue Exception => e
              deal_io_exception( reads[ sock ], sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            mirr = twins[ sock ]
            unless mirr
              appd = pending_apps[ sock ]
              appd_info = appd_infos[ appd ]
              appd_info[ :pending_apps ][ sock ] << data
              next
            end

            buffs[ mirr ] << data
            writes[ mirr ] = :mirr
            timestamps[ mirr ] = now
          when :mirr
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            rescue Exception => e
              deal_io_exception( reads[ sock ], sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            app = twins[ sock ]
            buffs[ app ] << data
            writes[ app ] = :app
            timestamps[ app ] = now

            appd = pending_apps[ app ]
            appd_info = appd_infos[ appd ]
            timestamps[ appd_info[ :room ] ] = now
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            check_timeout( 'w', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
            next
          rescue Exception => e
            deal_io_exception( writes[ sock ], sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
            next
          end

          timestamps[ sock ] = Time.new
          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          e = close_after_writes.delete( sock )

          if e
            sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
            close_socket( sock, reads, buffs, writes, timestamps, twins )
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def check_timeout( mode, sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
      if Time.new - timestamps[ sock ] >= 5
        role = ( mode == 'r' ? reads[ sock ] : writes[ sock ] )
        puts "#{ role } #{ mode } #{ e.class } timeout"
        deal_io_exception( role, sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
      end
    end

    def deal_io_exception( role, sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos )
      twin = close_socket( sock, reads, buffs, writes, timestamps, twins )

      if twin
        if writes.include?( twin )
          reads.delete( twin )
          twins.delete( twin )
          close_after_writes[ twin ] = e
        else
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
          close_socket( twin, reads, buffs, writes, timestamps, twins )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end

      writable_socks.delete( sock )

      case role
      when :room
        appd, appd_info = appd_infos.find{ | _, info | info[ :room ] == sock }

        if appd
          appd_port = appd.local_address.ip_unpack.last
          appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
          close_socket( appd, reads, buffs, writes, timestamps, twins )

          begin
            File.delete( appd_info[ :tmp_path ] )
          rescue Errno::ENOENT
          end

          mirrd = appd_info[ :mirrd ]
          mirrd_port = mirrd.local_address.ip_unpack.last
          mirrd.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
          close_socket( mirrd, reads, buffs, writes, timestamps, twins )

          appd_info[ :pending_apps ].each do | app, _ |
            app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( app, reads, buffs, writes, timestamps, twins )
            pending_apps.delete( app )
          end

          appd_info[ :linked_apps ].each do | app, mirr |
            app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( app, reads, buffs, writes, timestamps, twins )
            pending_apps.delete( app )
            mirr.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            close_socket( mirr, reads, buffs, writes, timestamps, twins )
          end

          appd_infos.delete( appd )
        end
      when :app
        appd = pending_apps.delete( sock )
        appd_info = appd_infos[ appd ]
        appd_info[ :pending_apps ].delete( sock )
        appd_info[ :linked_apps ].delete( sock )
      when :mirr
        if twin
          appd = pending_apps.delete( twin )
          appd_info = appd_infos[ appd ]
          appd_info[ :pending_apps ].delete( twin )
          appd_info[ :linked_apps ].delete( twin )
        end
      end
    end

    def close_socket( sock, reads, buffs, writes, timestamps, twins )
      sock.close
      reads.delete( sock )
      buffs.delete( sock )
      writes.delete( sock )
      timestamps.delete( sock )
      twins.delete( sock )
    end

  end
end
