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
require 'nio'
require 'socket'

module Girl
  class Mirror

    def initialize( roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22, timeout = 1800, room_title = nil, chunk_dir = '/tmp/mirror', managed_sock = nil )
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/mirror/{pid}-{object_id}.0, ... ] }
      @close_after_writes = []
      @roomd_host = roomd_host
      @roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      @room_title = room_title
      @appd_host = appd_host
      @appd_port = appd_port
      @appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      @chunk_dir = chunk_dir
      @selector = NIO::Selector.new
      @roles = {}  # mon => :room / :mirr / :app / :managed
      @timestamps = {} # mon => last r/w
      @twins = {} # mirr_mon <=> app_mon
      @timeout = timeout

      connect_roomd

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
            when :room
              now = Time.new

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ETIMEDOUT => e
                puts "#{ now } read #{ @roles[ mon ] } #{ e.class }"

                if e.is_a?( EOFError )
                  connect_roomd
                else
                  sock.close
                end

                break
              end

              @timestamps[ mon ] = now

              data.split( ';' ).map{ | s | s.to_i }.each do | mirrd_port |
                mirr = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
                app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

                begin
                  mirr.connect_nonblock( Socket.sockaddr_in( mirrd_port, @roomd_host ) )
                rescue IO::WaitWritable, Errno::EINTR
                rescue Errno::EADDRNOTAVAIL => e
                  puts "connect mirrd #{ @roomd_host }:#{ mirrd_port } #{ e.class }"
                  mirr.close
                  next
                end

                begin
                  app.connect_nonblock( @appd_sockaddr )
                rescue IO::WaitWritable, Errno::EINTR
                rescue Errno::EADDRNOTAVAIL => e
                  puts "connect appd #{ @appd_host }:#{ @appd_port } #{ e.class }"
                  app.close
                  next
                end

                @buffs[ mirr ] = ''
                @chunks[ mirr ] = { seed: 0, files: [] }
                @buffs[ app ] = ''
                @chunks[ app ] = { seed: 0, files: [] }

                mirr_mon = @selector.register( mirr, :r )
                app_mon = @selector.register( app, :r )
                @roles[ mirr_mon ] = :mirr
                @timestamps[ mirr_mon ] = now
                @twins[ mirr_mon ] = app_mon
                @roles[ app_mon ] = :app
                @timestamps[ app_mon ] = now
                @twins[ app_mon ] = mirr_mon
              end
            when :mirr
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin.io.closed?
                close_mon( mon )
                next
              end

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              @timestamps[ mon ] = Time.new
              buffer( twin, data )
            when :app
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin.io.closed?
                close_mon( mon )
                next
              end

              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              @timestamps[ mon ] = Time.new
              buffer( twin, data )
            when :managed
              data, addrinfo, rflags, *controls = sock.recvmsg
              data = data.strip

              if data == 't'
                now = Time.new
                puts "p#{ Process.pid } check timeout #{ now }"

                unless @timestamps.find{ | _, stamp | now - stamp < @timeout }
                  puts "flash #{ now }"
                  connect_roomd
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

    def connect_roomd
      @roles.select{ | _, role | role != :managed  }.each do | mon, _ |
        sock = mon.io
        sock.close
        @selector.deregister( sock )
        @roles.delete( mon )
      end

      @chunks.each do | sock, chunk |
        chunk[ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      @writes.clear
      @buffs.clear
      @caches.clear
      @chunks.clear
      @close_after_writes.clear
      @timestamps.clear
      @twins.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

      begin
        sock.connect_nonblock( @roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
      rescue Errno::ENETUNREACH => e
        puts "#{ Time.new } connect roomd #{ e.class }"
        sock.close
        return
      end

      @buffs[ sock ] = ''
      @chunks[ sock ] = { seed: 0, files: [] }
      mon = @selector.register( sock, :r )
      @roles[ mon ] = :room
      @timestamps[ mon ] = Time.new

      if @room_title
        buffer( mon, @room_title.unpack( "C*" ).map{ | c | c.chr }.join )
      end
    end

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

      @chunks[ sock ][ :files ].each do | path |
        begin
          File.delete( path )
        rescue Errno::ENOENT
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
    end

  end
end
