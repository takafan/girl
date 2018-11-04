require 'girl/xeh'
require 'socket'

module Girl
  class Relayd

    def initialize( port, xeh_block = nil, chunk_dir = '/tmp/relayd' )
      if xeh_block
        Girl::Xeh.class_eval( xeh_block )
      end

      @reads = [] # socks
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/relayd/{pid}-{object_id}.0, ... ] }
      @roles = {} # :relayd / :relay / :dest
      @timestamps = {} # relay / dest => last r/w
      @twins = {} # relay <=> dest
      @close_after_writes = {} # sock => exception
      @addrs = {} # sock => addrinfo
      @xeh = Girl::Xeh.new
      @chunk_dir = chunk_dir

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
        readable_socks, writable_socks = IO.select( @reads, @writes.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :relayd
            now = Time.new
            print "p#{ Process.pid } #{ now } "

            @timestamps.select{ | _, stamp | now - stamp > 600 }.each do | so, _ |
              close_socket( so )
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
            @buffs[ relay ] = ''
            @chunks[ relay ] = { seed: 0, files: [] }
            @timestamps[ relay ] = now
            @addrs[ relay ] = addr
          when :relay
            dest = @twins[ sock ]

            if dest && dest.closed?
              close_socket( sock )
              next
            end

            begin
              data = @xeh.swap( sock.read_nonblock( 4096 ) )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )

              if dest
                @close_after_writes[ dest ] = e
              end

              next
            end

            @timestamps[ sock ] = Time.new

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
              begin
                dest.connect_nonblock( Socket.sockaddr_in( dst_port, dst_host ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "connect destination #{ e.class }"
                dest.close
                next
              end

              @reads << dest
              @roles[ dest ] = :dest
              @buffs[ dest ] = ''
              @chunks[ dest ] = { seed: 0, files: [] }
              @timestamps[ dest ] = Time.new
              @twins[ dest ] = sock
              @twins[ sock ] = dest

              if data.empty?
                next
              end
            end

            buffer( dest, data )
          when :dest
            relay = @twins[ sock ]

            if relay.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              @close_after_writes[ relay ] = e
              next
            end

            @timestamps[ sock ] = Time.new
            buffer( relay, @xeh.swap( data ) )
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
            close_socket( sock )

            if @twins[ sock ]
              @close_after_writes[ @twins[ sock ] ] = e
            end

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
        unless @close_after_writes[ sock ].is_a?( EOFError )
          sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        end

        close_socket( sock )
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
