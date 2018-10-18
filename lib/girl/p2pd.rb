require 'socket'

module Girl
  class P2pd

    def initialize( roomd_port = 6262, tmp_dir = '/tmp/p2pd', room_timeout = 3600 )
      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 ) # avoid EADDRINUSE after a restart
      roomd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd.listen( 5 )
      puts "roomd listening on #{ roomd_port }"

      reads = {
        roomd => :roomd # :roomd / :room
      }
      buffs = {} # sock => ''
      writes = {} # sock => :room
      timestamps = {} # sock => push_to_reads_or_writes.timestamp
      infos = {} # pending_room => { ip_port: '6.6.6.6:12345', tmp_path: '/tmp/p2pr/6.6.6.6:12345' }

      Dir.mkdir( tmp_dir ) unless Dir.exist?( tmp_dir )

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys )

        readable_socks.each do | sock |
          case reads[ sock ]
          when :roomd
            now = Time.new

            timestamps.select{ | _, stamp | now - stamp > room_timeout }.each do | room, _ |
              close_socket( room, reads, buffs, writes, timestamps, infos, writable_socks )
            end

            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            end

            reads[ room ] = :room
            buffs[ room ] = ''
            timestamps[ room ] = now
            ip_port = addr.ip_unpack.join( ':' )
            tmp_path = File.join( tmp_dir, ip_port )
            File.open( tmp_path, 'w' )
            infos[ room ] = {
              ip_port: ip_port,
              tmp_path: tmp_path
            }
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, infos, writable_socks )
              next
            rescue Exception => e
              close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            if data[ 0, 4 ] == 'room' # p1 set room title
              info = infos[ sock ]

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
                close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
                next
              end

              info[ :tmp_path ] = tmp_path
            elsif data[ 0, 4 ] == 'come' # connect me!
              p2_info = infos[ sock ]

              ip_port = data[ 4..-1 ]
              p1_room, p1_info = infos.find{ |_, info| info[ :ip_port ] == ip_port }

              unless p1_info
                sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
                next
              end

              buffs[ p1_room ] << p2_info[ :ip_port ]
              writes[ p1_room ] = :room

              begin
                File.delete( p1_info[ :tmp_path ] )
              rescue Errno::ENOENT
              end

              begin
                File.delete( p2_info[ :tmp_path ] )
              rescue Errno::ENOENT
              end

              infos.delete( p1_room )
              infos.delete( sock )
            end
          end
        end

        writable_socks.each do |sock|
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable
            check_timeout( 'w', sock, reads, buffs, writes, timestamps, infos, writable_socks )
            next
          rescue Exception => e
            close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
            next
          end

          timestamps[ sock ] = Time.new
          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def check_timeout( mode, sock, reads, buffs, writes, timestamps, infos, writable_socks )
      if Time.new - timestamps[ sock ] >= 5
        puts "#{ mode == 'r' ? reads[ sock ] : writes[ sock ] } #{ mode } #{ e.class } timeout"
        close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
      end
    end

    def close_socket( sock, reads, buffs, writes, timestamps, infos, writable_socks )
      sock.close
      reads.delete( sock )
      buffs.delete( sock )
      writes.delete( sock )
      timestamps.delete( sock )
      info = infos.delete( sock )

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
