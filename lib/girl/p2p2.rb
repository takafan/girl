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
require 'nio'
require 'socket'

module Girl
  class P2p2

    def initialize( roomd_host, roomd_port, p1_info, tmp_dir = '/tmp/p2p2' )
      @writes = {} # sock => ''
      @p1_info = p1_info
      @tmp_dir = tmp_dir
      @tmp_path = ''
      hidx = p1_info.index( '-' )
      p1_info = p1_info[ 0, hidx ] if hidx
      p1_host, p1_port = p1_info.split( ':' )
      @p1_sockaddr = Socket.sockaddr_in( p1_port, p1_host )
      @rep2p = 0
      @usr = Girl::Usr.new
      @selector = NIO::Selector.new
      @roles = {} # mon => :room / :p2 / :appd / :app
      @twins = {} # p2_mon <=> app_mon
      @swaps = [] # p2_mons
      @swaps2 = {} # p2_mon => nil or length

      room = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      room.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        room.connect_nonblock( Socket.sockaddr_in( roomd_port, roomd_host ) )
      rescue IO::WaitWritable, Errno::EINTR
      end

      @writes[ room ] = ''
      mon = @selector.register( room, :r )
      @roles[ mon ] = :room
      @p2p_after_write = true
      buffer( mon, "come#{ p1_host }:#{ p1_port }" )
    end

    def looping
      loop do
        @selector.select do | mon |
          sock = mon.io

          if mon.readable?
            case @roles[ mon ]
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

              puts 'ghost?'
            when :appd
              begin
                app, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              if @roles.find{ | _, role | role == :app }
                puts 'ignore second'
                app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                app.close
                next
              end

              @writes[ app ] = ''
              p2_mon, _ = @roles.find{ | _, role | role == :p2 }
              app_mon = @selector.register( app, :r )
              @roles[ app_mon ] = :app
              @twins[ app_mon ] = p2_mon
              @twins[ p2_mon ] = app_mon
              buffer( p2_mon, '!' )
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
                @writes.delete( sock )
                @selector.deregister( sock )
                @roles.delete( mon )
                @swaps.delete( mon )
                @swaps2.delete( mon )
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

              if @swaps2.include?( mon )
                len = @swaps2[ mon ]

                unless len
                  if data.size < 2
                    raise "lonely char? #{ data.inspect }"
                  end

                  len = data[ 0, 2 ].unpack( 'n' ).first
                  data = data[ 2..-1 ]
                end

                if data.size >= len
                  data = "#{ @usr.swap( data[ 0, len ] ) }#{ data[ len..-1 ] }"
                  @swaps2.delete( mon )
                else
                  data = @usr.swap( data )
                  @swaps2[ mon ] = len - data.size
                end
              end

              buffer( @twins[ mon ], data )
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

              twin = @twins[ mon ]

              if @swaps.delete( twin )
                data = "#{ [ data.size ].pack( 'n' ) }#{ @usr.swap( data ) }"
              end

              buffer( twin, data )
            end
          end

          if mon.writable?
            data = @writes[ sock ]

            begin
              written = sock.write_nonblock( data )
            rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
              next
            rescue Exception => e
              begin
                File.delete( @tmp_path )
              rescue Errno::ENOENT
              end

              raise e
            end

            @writes[ sock ] = data[ written..-1 ]

            unless @writes[ sock ].empty?
              next
            end

            mon.remove_interest( :w )

            if @p2p_after_write
              p2p

              appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
              appd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
              appd.listen( 5 )
              puts "appd listening on #{ appd.local_address.ip_unpack.join(':') }"

              @writes[ appd ] = ''
              @tmp_path = File.join( @tmp_dir, "#{ appd.local_address.ip_unpack.last }--#{ @p1_info }" )
              File.open( @tmp_path, 'w' )
              appd_mon = @selector.register( appd, :r )
              @roles[ appd_mon ] = :appd
              @p2p_after_write = false
            end
          end
        end
      end
    end

    def quit!
      @roles.each{ | mon, _ | mon.io.close }
      exit
    end

    private

    def buffer( mon, data )
      @writes[ mon.io ] << data
      mon.add_interest( :w )
    end

    def p2p
      p2 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      p2.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      room_mon, _ = @roles.find{ | _, role | role == :room }
      p2.bind( room_mon.io.local_address ) # use the hole

      begin
        p2.connect_nonblock( @p1_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
      end

      @writes[ p2 ] = ''
      p2_mon = @selector.register( p2, :r )
      @roles[ p2_mon ] = :p2
      @swaps << p2_mon
      @swaps2[ p2_mon ] = nil
    end

  end
end
