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

    def initialize( socks_host, socks_port, resolv_host, resolv_port, relayd_host, relayd_port )
      @reads = []
      @writes = {} # sock => ''
      @roles = {} # :socks5 / :source / :relay
      @procs = {} # source => :connect / :request / :passing
      @timestamps = {} # source / relay => last r/w
      @twins = {} # source <=> relay
      @close_after_writes = {} # sock => exception
      @dns = Resolv::DNS.new( nameserver_port: [ [ resolv_host, resolv_port ] ] )
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new

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
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :socks5
            print "p#{ Process.pid } #{ Time.new } "

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            @reads << source
            @roles[ source ] = :source
            @writes[ source ] = ''
            @timestamps[ source ] = Time.new
            @procs[ source ] = :connect
          when :source
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_socket( sock )

              if @twins[ sock ]
                @close_after_writes[  @twins[ sock ] ] = e
              end

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

              @writes[ sock ] << [ 5, 0 ].pack( 'C2' )
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

              @reads << relay
              @roles[ relay ] = :relay
              @writes[ relay ] = @hex.swap( @hex.mix( dst_host, dst_port ) )
              @timestamps[ relay ] = now
              @twins[ relay ] = sock
              @twins[ sock ] = relay

              # +----+-----+-------+------+----------+----------+
              # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
              # +----+-----+-------+------+----------+----------+
              # | 1  |  1  | X'00' |  1   | Variable |    2     |
              # +----+-----+-------+------+----------+----------+

              _, sock_port, sock_host = sock.getsockname.unpack( 'nnN' )
              @writes[ sock ] << [ 5, 0, 0, 1, sock_host, sock_port ].pack( 'C4Nn' )
              @procs[ sock ] = :passing
            elsif @procs[ sock ] == :passing
              relay = @twins[ sock ]
              @writes[ relay ] << @hex.swap( data )
              @timestamps[ relay ] = now
            end
          when :relay
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              close_socket( sock )

              if @twins[ sock ]
                @close_after_writes[  @twins[ sock ] ] = e
              end

              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            source = @twins[ sock ]
            @writes[ source ] << @hex.swap( data )
            @timestamps[ source ] = now
          end
        end

        writable_socks.each do | sock |
          if sock.closed?
            next
          end

          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            next
          rescue Exception => e
            close_socket( sock )

            if @twins[ sock ]
              @close_after_writes[  @twins[ sock ] ] = e
            end

            next
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          if @writes[ sock ].empty? && @close_after_writes.include?( sock )
            unless @close_after_writes[ sock ].is_a?( EOFError )
              sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
            end

            close_socket( sock )
          end
        end
      end
    end

    def quit!
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear
      @close_after_writes.clear
      exit
    end

    private

    def close_socket( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
      @close_after_writes.delete( sock )
    end

  end
end
