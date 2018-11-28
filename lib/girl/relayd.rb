require 'girl/xeh'
require 'nio'
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
      @close_after_writes = []
      @addrs = {} # sock => addrinfo
      @xeh = Girl::Xeh.new
      @chunk_dir = chunk_dir
      @selector = NIO::Selector.new
      @timestamps = {} # relay_mon / dest_mon => last r/w
      @twins = {} # relay_mon <=> dest_mon

      relayd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relayd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relayd.bind( Socket.pack_sockaddr_in( port, '0.0.0.0' ) )
      relayd.listen( 511 )
      puts "p#{ Process.pid } listening on #{ port } #{ @selector.backend }"

      @reads << relayd
      @roles[ relayd ] = :relayd
      @clean_stamp = Time.new # daily clean job, retire clients that idled 1 day
      @selector.register( relayd, :r )
    end

    def looping
      loop do
        @selector.select do | mon |
          sock = mon.io

          if mon.readable?
            case @roles[ sock ]
            when :relayd
              now = Time.new
              print "p#{ Process.pid } #{ now } "

              if now - @clean_stamp > 86400
                @timestamps.select{ | _, stamp | now - stamp > 86400 }.each do | mo, _ |
                  close_mon( mo )
                end

                @clean_stamp = now
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
              @addrs[ relay ] = addr
              relay_mon = @selector.register( relay, :r )
              @timestamps[ relay_mon ] = now
            when :relay
              if sock.closed?
                next
              end

              twin = @twins[ mon ]

              if twin && twin.io.closed?
                close_mon( mon )
                next
              end

              begin
                data = @xeh.swap( sock.read_nonblock( 4096 ) )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              @timestamps[ mon ] = Time.new

              unless twin
                ret = @xeh.decode( data, @addrs.delete( sock ) )

                unless ret[ :success ]
                  puts ret[ :error ]
                  sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  close_mon( mon )
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

                twin = @selector.register( dest, :r )
                @timestamps[ twin ] = Time.new
                @twins[ twin ] = mon
                @twins[ mon ] = twin

                if data.empty?
                  next
                end
              end

              buffer( twin, data )
            when :dest
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
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              @timestamps[ mon ] = Time.new
              buffer( twin, @xeh.swap( data ) )
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
      @close_after_writes.clear
      @selector.close
      @timestamps.clear
      @twins.clear

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
      @timestamps[ mon ] = Time.new
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

      @reads.delete( sock )
      @writes.delete( sock )
      @buffs.delete( sock )
      @caches.delete( sock )
      @chunks.delete( sock )
      @roles.delete( sock )
      @close_after_writes.delete( sock )
      @selector.deregister( sock )
      @timestamps.delete( mon )
      @twins.delete( mon )
    end

  end
end
