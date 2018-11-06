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

    def initialize( roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22, timeout = 1800, room_title = nil, chunk_dir = '/tmp/mirror' )
      @reads = []
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/mirror/{pid}-{object_id}.0, ... ] }
      @roles = {}  # sock => :room / :mirr / :app
      @timestamps = {} # sock => last r/w
      @twins = {} # mirr <=> app
      @close_after_writes = []
      @roomd_host = roomd_host
      @roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      @room_title = room_title
      @appd_host = appd_host
      @appd_port = appd_port
      @appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      @timeout = timeout
      @reconn = 0
      @chunk_dir = chunk_dir

      connect_roomd
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.keys, [], @timeout )

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

              @reads << mirr
              @roles[ mirr ] = :mirr
              @buffs[ mirr ] = ''
              @chunks[ mirr ] = { seed: 0, files: [] }
              @timestamps[ mirr ] = now
              @twins[ mirr ] = app

              @reads << app
              @roles[ app ] = :app
              @buffs[ app ] = ''
              @chunks[ app ] = { seed: 0, files: [] }
              @timestamps[ app ] = now
              @twins[ app ] = mirr
            end
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

            @timestamps[ sock ] = Time.new
            buffer( app, data )
          when :app
            if sock.closed?
              next
            end

            mirr = @twins[ sock ]

            if mirr.closed?
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
            buffer( mirr, data )
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
      clear_all!
      exit
    end

    private

    def clear_all!
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
    end

    def connect_roomd
      clear_all!
      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

      begin
        sock.connect_nonblock( @roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
        @reads << sock
        @roles[ sock ] = :room
        @buffs[ sock ] = ''
        @chunks[ sock ] = { seed: 0, files: [] }

        if @room_title
          buffer( sock, @room_title.unpack( "C*" ).map{ | c | c.chr }.join )
        end
      end
    end

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
      sock.close
      @chunks[ sock ][ :files ].each do | path |
        begin
          File.delete( path )
        rescue Errno::ENOENT
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
    end

  end
end
