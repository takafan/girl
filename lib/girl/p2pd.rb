require 'nio'
require 'socket'

module Girl
  class P2pd

    def initialize( roomd_port = 6262, tmp_dir = '/tmp/p2pd', timeout = 3600, managed_sock = nil )
      @writes = {} # sock => ''
      @tmp_dir = tmp_dir
      @timeout = timeout
      @selector = NIO::Selector.new
      @roles = {} # mon => :roomd / :room / :managed
      @infos = {} # room_mon => { ip_port: '6.6.6.6:12345', tmp_path: '/tmp/p2pd/6.6.6.6:12345' }
      @timestamps = {} # mon => last r/w

      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 127 )
      puts "roomd listening on #{ roomd_port } #{ @selector.backend }"
      roomd_mon = @selector.register( roomd, :r )
      @roles[ roomd_mon ] = :roomd

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
            when :roomd
              begin
                room, addr = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR
                next
              end

              room.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
              @writes[ room ] = ''
              ip_port = addr.ip_unpack.join( ':' )
              tmp_path = File.join( @tmp_dir, ip_port )
              File.open( tmp_path, 'w' )

              room_mon = @selector.register( room, :r )
              @roles[ room_mon ] = :room
              @infos[ room_mon ] = {
                ip_port: ip_port,
                tmp_path: tmp_path
              }
              @timestamps[ room_mon ] = Time.new
            when :room
              begin
                data = sock.read_nonblock( 4096 )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable
                next
              rescue Exception => e
                close_mon( mon )
                next
              end

              @timestamps[ mon ] = Time.new

              if data[ 0, 4 ] == 'room' # p1 set room title
                info = @infos[ mon ]

                begin
                  File.delete( info[ :tmp_path ] )
                rescue Errno::ENOENT
                end

                room_title = data[ 4..-1 ]
                tmp_path = "#{ info[ :tmp_path ] }-#{ room_title }"

                begin
                  File.open( tmp_path, 'w' )
                rescue Errno::ENOENT, ArgumentError => e
                  puts "open tmp path #{ e.class }"
                  close_mon( mon )
                  next
                end

                info[ :tmp_path ] = tmp_path
              elsif data[ 0, 4 ] == 'come' # connect me!
                p2_info = @infos[ mon ]

                ip_port = data[ 4..-1 ]
                p1_room_mon, p1_info = @infos.find{ |_, info| info[ :ip_port ] == ip_port }

                unless p1_info
                  sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  close_mon( mon )
                  next
                end

                @writes[ p1_room_mon.io ] << p2_info[ :ip_port ]
                p1_room_mon.add_interest( :w )

                begin
                  File.delete( p1_info[ :tmp_path ] )
                rescue Errno::ENOENT
                end

                begin
                  File.delete( p2_info[ :tmp_path ] )
                rescue Errno::ENOENT
                end

                @infos.delete( p1_room_mon )
                @infos.delete( mon )
              else
                puts 'ghost?'
              end
            when :managed
              data, addrinfo, rflags, *controls = sock.recvmsg
              data = data.strip

              if data == 't'
                now = Time.new
                puts "p#{ Process.pid } check timeout #{ now }"

                @timestamps.select{ | _, stamp | now - stamp > @timeout }.each do | mo, _ |
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

            data = @writes[ sock ]

            begin
              written = sock.write_nonblock( data )
            rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable
              next
            rescue Exception => e
              close_mon( mon )
              next
            end

            @timestamps[ mon ] = Time.new
            @writes[ sock ] = data[ written..-1 ]

            unless @writes[ sock ].empty?
              next
            end

            mon.remove_interest( :w )
          end
        end
      end
    end

    def quit!
      @roles.each{ | mon, _ | mon.io.close }
      @infos.each do | _, info |
        begin
          File.delete( info[ :tmp_path ] )
        rescue Errno::ENOENT
        end
      end

      exit
    end

    private

    def close_mon( mon )
      sock = mon.io
      sock.close

      @writes.delete( sock )
      @selector.deregister( sock )
      @roles.delete( mon )
      info = @infos.delete( mon )

      if info
        begin
          File.delete( info[ :tmp_path ] )
        rescue Errno::ENOENT
        end
      end

      @timestamps.delete( mon )
    end

  end
end
