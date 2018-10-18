require 'socket'

module Girl
  class P2p1

    def initialize( roomd_host, roomd_port, appd_host, appd_port, timeout = 1800, room_title = nil )
      reads = {}  # sock => :room / :p1 / :app
      buffs = {} # sock => ''
      writes = {} # sock => :room / :p1 / :app
      timestamps = {} # sock => push_to_reads_or_writes.timestamp
      twins = {} # p1 <=> app
      roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
      appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      reconn = 0

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys, [], timeout )

        unless readable_socks
          puts "flash #{ Time.new }"
          connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
          next
        end

        readable_socks.each do | sock |
          case reads[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
              reconn = 0
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, e, roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              next
            rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ETIMEDOUT => e
              if e.is_a?( EOFError )
                reconn = 0
              elsif reconn > 100
                raise e
              else
                reconn += 1
              end

              sleep 5
              puts "#{ e.class }, reconn #{ reconn }"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )

              break
            end

            if reads.find{ | _, role | role == :p1 }
              next
            end

            now = Time.new
            timestamps[ sock ] = now
            p2_ip, p2_port = data.split( ':' )

            p1 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            p1.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

            begin
              p1.bind( sock.local_address ) # use the hole
            rescue Errno::EADDRINUSE => e # SO_REUSEADDR could reuse a TIME_WAIT port, but not other
              puts "bind #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              break
            end

            reads[ p1 ] = :p1
            buffs[ p1 ] = ''
            timestamps[ p1 ] = now

            begin
              p1.connect_nonblock( Socket.sockaddr_in( p2_port, p2_ip ) )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              puts "p2p #{ p2_ip }:#{ p2_port } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              break
            end
          when :p1
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, e, roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              next
            rescue Exception => e
              puts "r #{ reads[ sock ] } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              break
            end

            now = Time.new
            timestamps[ sock ] = now
            app = twins[ sock ]

            unless app
              app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              reads[ app ] = :app
              buffs[ app ] = ''
              timestamps[ app ] = now
              twins[ app ] = sock
              twins[ sock ] = app

              begin
                app.connect_nonblock( appd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "c appd #{ appd_host }:#{ appd_port } #{ e.class }, flash a room"
                connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
                break
              end

              if data[ 0 ] == '!' # here comes a new app!
                data = data[ 1..-1 ]
                if data.empty?
                  next
                end
              end
            end

            buffs[ app ] << data
            writes[ app ] = :app
            timestamps[ app ] = now
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, e, roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              next
            rescue Exception => e
              puts "r #{ reads[ sock ] } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
              break
            end

            now = Time.new
            timestamps[ sock ] = now

            p1 = twins[ sock ]
            buffs[ p1 ] << data
            writes[ p1 ] = :p1
            timestamps[ p1 ] = now
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            check_timeout( 'w', sock, e, roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
            next
          rescue Exception => e
            puts "w #{ writes[ sock ] } #{ e.class }, flash a room"
            connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
            break
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

    def check_timeout( mode, sock, e, roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
      if Time.new - timestamps[ sock ] >= 5
        puts "#{ mode == 'r' ? reads[ sock ] : writes[ sock ] } #{ mode } #{ e.class } timeout"
        connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
      end
    end

    def connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, room_title )
      reads.keys.each{ | sock | sock.close }
      reads.clear
      buffs.clear
      writes.clear
      timestamps.clear
      twins.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        sock.connect_nonblock( roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
        reads[ sock ] = :room

        if room_title
          buffs[ sock ] = "room#{ room_title }".unpack( "C*" ).map{ |c| c.chr }.join
          writes[ sock ] = :room
        end
      end
    end
  end
end
