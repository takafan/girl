##
# usage:
#
# 1. Girl::P2pd.new( 6262, '/tmp/p2pd' ).looping # @server
#
# 2. Girl::P2p1.new( '{ your.server.ip }', 6262, '127.0.0.1', 22, 1800, '周立波' ).looping # @home
#
# 3. echo "ls -lt" | sftp -q root@{ your.server.ip }:/tmp/p2pd # @company, saw 6.6.6.6:12345-周立波
#
# 4. Girl::P2p2.new( 'your.server.ip', 6262, '6.6.6.6:12345-周立波', '/tmp/p2p2' ).looping
#
# 5. ls -lt /tmp/p2p2 # saw 45678--6.6.6.6:12345-周立波
#
# 6. ssh -p45678 libo@127.0.0.1
#
require 'girl/usr'
require 'socket'

module Girl
  class P2p2

    def initialize( roomd_host, roomd_port, p1_info, tmp_dir = '/tmp/p2p2' )
      @reads = []
      @writes = {} # sock => ''
      @roles = {} # sock => :room / :p2 / :appd / :app
      @timestamps = {} # sock => last r/w
      @twins = {} # app <=> p2
      @p1_info = p1_info
      @tmp_dir = tmp_dir
      @connect_p1_after_write = true
      @tmp_path = ''
      p1_host, p1_port = p1_info[ 0, p1_info.index( '-' ) ].split( ':' )
      @p1_sockaddr = Socket.sockaddr_in( p1_port, p1_host )
      @rep2p = 0
      @usr = Girl::Usr.new

      room = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      room.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        room.connect_nonblock( Socket.sockaddr_in( roomd_port, roomd_host ) )
      rescue IO::WaitWritable, Errno::EINTR
      end

      @reads << room
      @roles[ room ] = :room
      @writes[ room ] = "come#{ p1_host }:#{ p1_port }"
      Dir.mkdir( tmp_dir ) unless Dir.exist?( tmp_dir )
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              begin
                File.delete( @tmp_path )
              rescue Errno::ENOENT
              end

              raise e
            end

            @timestamps[ sock ] = Time.new
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            if @roles.find{ | _, role | role == :app }
              app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
              app.close
              next
            end

            now = Time.new

            p2, _ = @roles.find{ | _, role | role == :p2 }
            @reads << app
            @roles[ app ] = :app
            @writes[ app ] = ''
            @timestamps[ app ] = now

            @twins[ app ] = p2
            @twins[ p2 ] = app
            @writes[ p2 ] = '!'
            @timestamps[ p2 ] = now
          when :p2
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Errno::ECONNREFUSED => e
              if @rep2p > 10
                begin
                  File.delete( @tmp_path )
                rescue Errno::ENOENT
                end

                raise e
              else
                @rep2p += 1
              end

              puts "#{ e.class }, rep2p #{ @rep2p }"
              sock.close
              @reads.delete( sock )
              @roles.delete( sock )
              @writes.delete( sock )
              sleep 1
              p2p
              break
            rescue Exception => e
              begin
                File.delete( @tmp_path )
              rescue Errno::ENOENT
              end

              e.is_a?( EOFError ) ? exit : raise( e )
            end

            now = Time.new
            @timestamps[ sock ] = now

            app = @twins[ sock ]
            @writes[ app ] << @usr.swap( data )
            @timestamps[ app ] = now
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              next
            rescue Exception => e
              begin
                File.delete( @tmp_path )
              rescue Errno::ENOENT
              end

              e.is_a?( EOFError ) ? exit : raise( e )
            end

            now = Time.new
            @timestamps[ sock ] = now

            p2 = @twins[ sock ]
            @writes[ p2 ] << @usr.swap( data )
            @timestamps[ p2 ] = now
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            next
          rescue Exception => e
            begin
              File.delete( @tmp_path )
            rescue Errno::ENOENT
            end

            raise e
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]

          unless @writes[ sock ].empty?
            next
          end

          if @connect_p1_after_write
            p2p

            appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            appd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
            appd.listen( 5 )
            puts "appd listening on #{ appd.local_address.ip_unpack.join(':') }"

            @reads << appd
            @roles[ appd ] = :appd
            @writes[ appd ] = ''
            @tmp_path = File.join( @tmp_dir, "#{ appd.local_address.ip_unpack.last }--#{ @p1_info }" )
            File.open( @tmp_path, 'w' )

            @connect_p1_after_write = false
          end
        end
      end
    end

    # quit! in Signal.trap :TERM
    def quit!
      @reads.each{ | sock | sock.close }
      @reads.clear
      @writes.clear
      @roles.clear
      @timestamps.clear
      @twins.clear

      exit
    end

    private

    def p2p
      p2 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      p2.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      room, _ = @roles.find{ | _, role | role == :room }
      p2.bind( room.local_address ) # use the hole

      begin
        p2.connect_nonblock( @p1_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
      end

      @reads << p2
      @roles[ p2 ] = :p2
      @writes[ p2 ] = ''
    end

  end
end
