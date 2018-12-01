##
# usage
# =====
#
# 1. Girl::Relayd.new( 8080 ).looping # @server
#
# 2. Girl::Redir.new( 1919, '{ your.server.ip }', 8080 ).looping # @home
#
# 3. dig +short www.google.com @127.0.0.1 -p1818 # dig with girl/resolv, got 216.58.217.196
#
# 4. iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# 5. curl https://www.google.com/
#
require 'girl/hex'
require 'nio'
require 'socket'

module Girl
  class Redir

    def initialize( redir_port, relayd_host, relayd_port, hex_block = nil, chunk_dir = '/tmp/redir' )
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/redir/{pid}-{object_id}.0, ... ] }
      @close_after_writes = []
      @chunk_dir = chunk_dir
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new
      @selector = NIO::Selector.new
      @roles = {} # mon => :redir / :source / :relay / :managed
      @timestamps = {} # mon => last r/w
      @twins = {} # source_mon <=> relay_mon
      @swaps = [] # mons

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 511 )
      puts "p#{ Process.pid } listening on #{ redir_port } #{ @selector.backend }"
      mon = @selector.register( redir, :r )
      @roles[ mon ] = :redir

      managed = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      managed.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      managed.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      managed.bind( Socket.pack_sockaddr_in( redir_port, '127.0.0.1' ) )
      puts "managed bound on #{ redir_port } #{ @selector.backend }"
      mon = @selector.register( managed, :r )
      @roles[ mon ] = :managed
    end

    def looping
      loop do
        @selector.select do | mon |
          sock = mon.io

          if mon.readable?
            case @roles[ mon ]
            when :redir
              now = Time.new
              print "p#{ Process.pid } #{ now } "

              begin
                source, _ = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              rescue Errno::EMFILE => e
                puts e.class
                quit!
              end

              source.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

              begin
                # https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
                dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
              rescue Exception => e
                puts "get SO_ORIGINAL_DST #{ e.class }"
                source.close
                next
              end

              dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
              relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

              begin
                relay.connect_nonblock( @relayd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "connect relayd #{ e.class }"
                relay.close
                next
              end

              @buffs[ source ] = ''
              @chunks[ source ] = { seed: 0, files: [] }
              @buffs[ relay ] = ''
              @chunks[ relay ] = { seed: 0, files: [] }

              source_mon = @selector.register( source, :r )
              relay_mon = @selector.register( relay, :r )
              @roles[ source_mon ] = :source
              @timestamps[ source_mon ] = now
              @twins[ source_mon ] = relay_mon
              @roles[ relay_mon ] = :relay
              @timestamps[ relay_mon ] = now
              @twins[ relay_mon ] = source_mon

              buffer( relay_mon, @hex.mix( dst_host, dst_port ) )
              @swaps << relay_mon
            when :source
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

              if @swaps.delete( twin )
                data = "#{ [ data.size ].pack( 'n' ) }#{ @hex.swap( data ) }"
              end

              buffer( twin, data )
            when :relay
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
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e  # WaitWritable for SSL renegotiation
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
                puts 'check timeout'
                now = Time.new

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
      @selector.deregister( sock )
      @roles.delete( mon )
      @timestamps.delete( mon )
      @twins.delete( mon )
      @swaps.delete( mon )
    end

  end
end
