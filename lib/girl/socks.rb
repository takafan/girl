##
# usage
# =====
#
# 1. Girl::Socks.new( '0.0.0.0', 1080, '127.0.0.1', 1818, '{ your.server.ip }', 8080 ).looping # @gateway
#
# 2. ALL_PROXY=socks5://192.168.1.59:1080 brew update # @mac
#
require 'girl/hex'
require 'nio'
require 'socket'
require 'resolv'

module Girl
  class Socks

    def initialize( socks_host, socks_port, resolv_host, resolv_port, relayd_host, relayd_port, chunk_dir = '/tmp/socks', managed_sock = nil )
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/socks/{pid}-{object_id}.0, ... ] }
      @close_after_writes = []
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new
      @procs = {} # source => :connect / :request / :passing
      @dns = Resolv::DNS.new( nameserver_port: [ [ resolv_host, resolv_port ] ] )
      @chunk_dir = chunk_dir
      @selector = NIO::Selector.new
      @roles = {} # mon => :socks5 / :source / :relay / :managed
      @timestamps = {} # mon => last r/w
      @twins = {} # source_mon <=> relay_mon
      @swaps = [] # mons

      socks5 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      socks5.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      socks5.bind( Socket.pack_sockaddr_in( socks_port, socks_host ) )
      socks5.listen( 511 )
      puts "p#{ Process.pid } listening on #{ socks_host }:#{ socks_port } #{ @selector.backend }"
      socks5_mon = @selector.register( socks5, :r )
      @roles[ socks5_mon ] = :socks5

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
            when :socks5
              now = Time.new
              print "p#{ Process.pid } #{ now } "

              begin
                source, _ = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              @buffs[ source ] = ''
              @chunks[ source ] = { seed: 0, files: [] }
              @procs[ source ] = :connect

              source_mon = @selector.register( source, :r )
              @roles[ source_mon ] = :source
              @timestamps[ source_mon ] = now
            when :source
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
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_by_exception( mon, e )
                next
              end

              now = Time.new
              @timestamps[ mon ] = now

              if @procs[ sock ] == :connect
                ver = data[ 0 ].unpack( 'C' ).first
                if ver != 5
                  sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  close_mon( mon )
                  next
                end

                buffer( mon, [ 5, 0 ].pack( 'C2' ) )
                @procs[ sock ] = :request
              elsif @procs[ sock ] == :request

                # +----+-----+-------+------+----------+----------+
                # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                # +----+-----+-------+------+----------+----------+
                # | 1  |  1  | X'00' |  1   | Variable |    2     |
                # +----+-----+-------+------+----------+----------+

                atyp = data[ 3 ].unpack( 'C' ).first

                case atyp
                when 1
                  dst_addr = data[ 4, 4 ]
                  dst_host = dst_addr.unpack( 'N' ).first
                  dst_port = data[ 8, 2 ].unpack( 'n' ).first
                when 3
                  len = data[ 4 ].unpack( 'C' ).first
                  domain_name = data[ 5, len ]
                  dst_port = data[ 5 + len, 2 ].unpack( 'n' ).first
                  ip = @dns.getaddress( domain_name ).to_s
                  dst_addr = Socket.sockaddr_in( dst_port, ip )
                  _, dst_port, dst_host = dst_addr.unpack( 'nnN' )
                else
                  sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  close_mon( mon )
                  next
                end

                relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

                begin
                  relay.connect_nonblock( @relayd_sockaddr )
                rescue IO::WaitWritable, Errno::EINTR
                rescue Exception => e
                  relay.close
                  next
                end

                @buffs[ relay ] = ''
                @chunks[ relay ] = { seed: 0, files: [] }

                twin = @selector.register( relay, :r )
                @roles[ twin ] = :relay
                @timestamps[ twin ] = now
                @twins[ twin ] = mon
                @twins[ mon ] = twin

                buffer( twin, @hex.mix( dst_host, dst_port ) )
                @swaps << twin

                # +----+-----+-------+------+----------+----------+
                # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                # +----+-----+-------+------+----------+----------+
                # | 1  |  1  | X'00' |  1   | Variable |    2     |
                # +----+-----+-------+------+----------+----------+

                _, sock_port, sock_host = sock.getsockname.unpack( 'nnN' )
                buffer( mon, [ 5, 0, 0, 1, sock_host, sock_port ].pack( 'C4Nn' ) )
                @procs[ sock ] = :passing
              elsif @procs[ sock ] == :passing
                if @swaps.delete( twin )
                  data = "#{ [ data.size ].pack( 'n' ) }#{ @hex.swap( data ) }"
                end

                buffer( twin, data )
              end
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
