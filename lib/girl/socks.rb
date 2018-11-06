##
# usage
# =====
#
# 1. Girl::Socks.new( '0.0.0.0', 1080, '127.0.0.1', 1818, 'your.server.ip', 8080 ).looping # @gateway
#
# 2. ALL_PROXY=socks5://192.168.1.59:1080 brew update # @mac
#
require 'socket'
require 'resolv'

module Girl
  class Socks

    def initialize( socks_host, socks_port, resolv_host, resolv_port, relayd_host, relayd_port, chunk_dir = '/tmp/socks' )
      @reads = [] # socks
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/socks/{pid}-{object_id}.0, ... ] }
      @roles = {} # :socks5 / :source / :relay
      @timestamps = {} # source / relay => last r/w
      @twins = {} # source <=> relay
      @close_after_writes = []
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new
      @procs = {} # source => :connect / :request / :passing
      @dns = Resolv::DNS.new( nameserver_port: [ [ resolv_host, resolv_port ] ] )
      @chunk_dir = chunk_dir

      socks5 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      socks5.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      socks5.bind( Socket.pack_sockaddr_in( socks_port, socks_host ) )
      socks5.listen( 128 )
      puts "p#{ Process.pid } listening on #{ socks_host }:#{ socks_port }"

      @reads << socks5
      @roles[ socks5 ] = :socks5
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :socks5
            now = Time.new
            print "p#{ Process.pid } #{ now } "

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            @reads << source
            @roles[ source ] = :source
            @buffs[ source ] = ''
            @chunks[ source ] = { seed: 0, files: [] }
            @timestamps[ source ] = now
            @procs[ source ] = :connect
          when :source
            if sock.closed?
              next
            end

            relay = @twins[ sock ]

            if relay && relay.closed?
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

            if @procs[ sock ] == :connect
              ver = data[ 0 ].unpack( 'C' ).first
              if ver != 5
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock )
                next
              end

              buffer( sock, [ 5, 0 ].pack( 'C2' ) )
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
                close_socket( sock )
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

              @twins[ sock ] = relay

              @reads << relay
              @roles[ relay ] = :relay
              @buffs[ relay ] = ''
              @chunks[ relay ] = { seed: 0, files: [] }
              @timestamps[ relay ] = now
              @twins[ relay ] = sock
              buffer( relay, @hex.swap( @hex.mix( dst_host, dst_port ) ) )

              # +----+-----+-------+------+----------+----------+
              # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
              # +----+-----+-------+------+----------+----------+
              # | 1  |  1  | X'00' |  1   | Variable |    2     |
              # +----+-----+-------+------+----------+----------+

              _, sock_port, sock_host = sock.getsockname.unpack( 'nnN' )
              buffer( sock, [ 5, 0, 0, 1, sock_host, sock_port ].pack( 'C4Nn' ) )
              @procs[ sock ] = :passing
            elsif @procs[ sock ] == :passing
              buffer( relay, @hex.swap( data ) )
            end
          when :relay
            if sock.closed?
              next
            end

            source = @twins[ sock ]

            if source.closed?
              close_socket( sock )
              next
            end

            begin
              data = @hex.swap( sock.read_nonblock( 4096 ) )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_by_exception( sock, e )
              next
            end

            @timestamps[ sock ] = Time.new
            buffer( source, data )
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
