require 'girl/xeh'
require 'nio'
require 'socket'

module Girl
  class Relayd

    def initialize( port, xeh_block = nil, chunk_dir = '/tmp/relayd', managed_sock = nil )
      if xeh_block
        Girl::Xeh.class_eval( xeh_block )
      end

      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/relayd/{pid}-{object_id}.0, ... ] }
      @close_after_writes = []
      @chunk_dir = chunk_dir
      @addrs = {} # sock => addrinfo
      @xeh = Girl::Xeh.new
      @selector = NIO::Selector.new
      @roles = {} # mon => :relayd / :relay / :dest / :managed
      @timestamps = {} # mon => last r/w
      @twins = {} # relay_mon <=> dest_mon
      @swaps = {} # relay_mon => nil or length

      relayd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      relayd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relayd.bind( Socket.pack_sockaddr_in( port, '0.0.0.0' ) )
      relayd.listen( 511 )
      puts "p#{ Process.pid } listening on #{ port } #{ @selector.backend }"
      relayd_mon = @selector.register( relayd, :r )
      @roles[ relayd_mon ] = :relayd

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
            when :relayd
              now = Time.new
              print "p#{ Process.pid } #{ now } "

              begin
                relay, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              rescue Errno::EMFILE => e
                puts e.class
                quit!
              end

              relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
              @buffs[ relay ] = ''
              @chunks[ relay ] = { seed: 0, files: [] }
              @addrs[ relay ] = addr
              relay_mon = @selector.register( relay, :r )
              @roles[ relay_mon ] = :relay
              @timestamps[ relay_mon ] = now
              @swaps[ relay_mon ] = nil
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
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              now = Time.new
              @timestamps[ mon ] = now

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

                @buffs[ dest ] = ''
                @chunks[ dest ] = { seed: 0, files: [] }

                twin = @selector.register( dest, :r )
                @roles[ twin ] = :dest
                @timestamps[ twin ] = now
                @twins[ twin ] = mon
                @twins[ mon ] = twin

                if data.empty?
                  next
                end
              end

              if @swaps.include?( mon )
                len = @swaps[ mon ]

                unless len
                  if data.size < 2
                    puts "lonely char? #{ data.inspect }"
                    sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                    close_mon( mon )
                    next
                  end

                  len = data[ 0, 2 ].unpack( 'n' ).first
                  data = data[ 2..-1 ]
                end

                if data.size >= len
                  data = "#{ @xeh.swap( data[ 0, len ] ) }#{ data[ len..-1 ] }"
                  @swaps.delete( mon )
                else
                  data = @xeh.swap( data )
                  @swaps[ mon ] = len - data.size
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
              buffer( twin, data )
            when :managed
              data, addrinfo, rflags, *controls = sock.recvmsg
              data = data.strip

              if data == 't'
                now = Time.new
                puts "p#{ Process.pid } check timeout #{ now }"

                @timestamps.select{ | _, stamp | now - stamp > 86400 }.each do | mo, _ |
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
      @addrs.delete( sock )
      @selector.deregister( sock )
      @roles.delete( mon )
      @timestamps.delete( mon )
      @twins.delete( mon )
      @swaps.delete( mon )
    end

  end
end
