require 'socket'

module Girl
  class P2pd

    def initialize( roomd_port = 6262, tmp_dir = '/tmp/p2pd', room_timeout = 3600 )
      @reads = []
      @writes = {} # sock => ''
      @roles = {} # :roomd / :room
      @timestamps = {} # sock => last r/w
      @tmp_dir = tmp_dir
      @room_timeout = room_timeout
      @infos = {} # pending_room => { ip_port: '6.6.6.6:12345', tmp_path: '/tmp/p2pr/6.6.6.6:12345' }

      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 5 )
      puts "roomd listening on #{ roomd_port }"

      @reads << roomd
      @roles[ roomd ] = :roomd
      Dir.mkdir( tmp_dir ) unless Dir.exist?( tmp_dir )
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.select{ | _, buff | !buff.empty? }.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :roomd
            now = Time.new

            @timestamps.select{ | _, stamp | now - stamp > @room_timeout }.each do | so, _ |
              close_socket( so, writable_socks )
            end

            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            @reads << room
            @roles[ room ] = :room
            @writes[ room ] = ''
            @timestamps[ room ] = now
            ip_port = addr.ip_unpack.join( ':' )
            tmp_path = File.join( @tmp_dir, ip_port )
            File.open( tmp_path, 'w' )
            @infos[ room ] = {
              ip_port: ip_port,
              tmp_path: tmp_path
            }
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable
              next
            rescue Exception => e
              close_socket( sock, writable_socks )
              next
            end

            now = Time.new
            @timestamps[ sock ] = now

            if data[ 0, 4 ] == 'room' # p1 set room title
              info = @infos[ sock ]

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
                close_socket( sock, writable_socks )
                next
              end

              info[ :tmp_path ] = tmp_path
            elsif data[ 0, 4 ] == 'come' # connect me!
              p2_info = @infos[ sock ]

              ip_port = data[ 4..-1 ]
              p1_room, p1_info = @infos.find{ |_, info| info[ :ip_port ] == ip_port }

              unless p1_info
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock, writable_socks )
                next
              end

              @writes[ p1_room ] << p2_info[ :ip_port ]

              begin
                File.delete( p1_info[ :tmp_path ] )
              rescue Errno::ENOENT
              end

              begin
                File.delete( p2_info[ :tmp_path ] )
              rescue Errno::ENOENT
              end

              @infos.delete( p1_room )
              @infos.delete( sock )
            end
          end
        end

        writable_socks.each do | sock |
          begin
            written = sock.write_nonblock( @writes[ sock ] )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable
            next
          rescue Exception => e
            close_socket( sock, writable_socks )
            next
          end

          @timestamps[ sock ] = Time.new
          @writes[ sock ] = @writes[ sock ][ written..-1 ]
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

      exit
    end

    private

    def close_socket( sock, writable_socks )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      info = @infos.delete( sock )

      if info
        begin
          File.delete( info[ :tmp_path ] )
        rescue Errno::ENOENT
        end
      end

      writable_socks.delete( sock )
    end

  end
end
