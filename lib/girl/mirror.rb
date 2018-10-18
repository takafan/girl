##
# usage
# =====
#
# 1. Girl::Mirrord.new( 6060, '127.0.0.1' ) # @server
#
# 2. Girl::Mirror.new( '{ your.server.ip }', 6060, '127.0.0.1', 22, 1800, '周立波' ) # @home
#
# 3. ls -lt /tmp/mirrord # @server, saw 45678-周立波
#
# 4. ssh -p45678 libo@localhost
#
require 'socket'

module Girl
  class Mirror

    def initialize( roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22, timeout = 1800, room_title = nil )
      reads = {}  # sock => :room / :mirr / :app
      buffs = {} # sock => ''
      writes = {} # sock => :room / :mirr / :app
      timestamps = {} # sock => push_to_reads_or_writes.timestamp
      twins = {} # mirr <=> app
      close_after_writes = {} # sock => exception
      roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, close_after_writes, room_title )
      appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      reconn = 0

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys, [], timeout )

        unless readable_socks
          puts "flash #{ Time.new }"
          connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, close_after_writes, room_title )
          next
        end

        readable_socks.each do | sock |
          case reads[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
              reconn = 0
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              if Time.new - timestamps[ sock ] >= 5
                puts "room r #{ e.class } timeout"
                connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, close_after_writes, room_title )
              end

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
              connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, close_after_writes, room_title )

              break
            end

            now = Time.new
            timestamps[ sock ] = now

            data.split( ';' ).map{ | s | s.to_i }.each do | mirrd_port |
              mirr = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

              reads[ mirr ] = :mirr
              buffs[ mirr ] = ''
              timestamps[ mirr ] = now
              twins[ mirr ] = app

              reads[ app ] = :app
              buffs[ app ] = ''
              timestamps[ app ] = now
              twins[ app ] = mirr

              begin
                mirr.connect_nonblock( Socket.sockaddr_in( mirrd_port, roomd_host ) )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect mirrd #{ roomd_host }:#{ mirrd_port } #{ e.class }"
                deal_io_exception( mirr, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
                next
              end

              begin
                app.connect_nonblock( appd_sockaddr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect appd #{ appd_host }:#{ appd_port } #{ e.class }"
                deal_io_exception( app, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
                next
              end
            end
          when :mirr
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            app = twins[ sock ]
            buffs[ app ] << data
            writes[ app ] = :app
            timestamps[ app ] = now
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
              check_timeout( 'r', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            rescue Exception => e
              deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
              next
            end

            now = Time.new
            timestamps[ sock ] = now

            mirr = twins[ sock ]
            buffs[ mirr ] << data
            writes[ mirr ] = :mirr
            timestamps[ mirr ] = now
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
            check_timeout( 'w', sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
            next
          rescue Exception => e
            deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
            next
          end

          timestamps[ sock ] = Time.new
          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          e = close_after_writes.delete( sock )

          if e
            sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
            close_socket( sock, reads, buffs, writes, timestamps, twins )
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def connect_roomd( roomd_sockaddr, reads, buffs, writes, timestamps, twins, close_after_writes, room_title )
      reads.keys.each{ | sock | sock.close }
      reads.clear
      buffs.clear
      writes.clear
      timestamps.clear
      twins.clear
      close_after_writes.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      begin
        sock.connect_nonblock( roomd_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR
        reads[ sock ] = :room

        if room_title
          buffs[ sock ] = room_title.unpack( "C*" ).map{ | c | c.chr }.join
          writes[ sock ] = :room
        end
      end
    end

    def check_timeout( mode, sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      if Time.new - timestamps[ sock ] >= 5
        role = ( mode == 'r' ? reads[ sock ] : writes[ sock ] )
        puts "#{ role } #{ mode } #{ e.class } timeout"
        deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      end
    end

    def deal_io_exception( sock, reads, buffs, writes, timestamps, twins, close_after_writes, e, readable_socks, writable_socks )
      twin = close_socket( sock, reads, buffs, writes, timestamps, twins )

      if twin
        if writes.include?( twin )
          reads.delete( twin )
          twins.delete( twin )
          close_after_writes[ twin ] = e
        else
          twin.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) ) unless e.is_a?( EOFError )
          close_socket( twin, reads, buffs, writes, timestamps, twins )
          writable_socks.delete( twin )
        end

        readable_socks.delete( twin )
      end

      writable_socks.delete( sock )
    end

    def close_socket( sock, reads, buffs, writes, timestamps, twins )
      sock.close
      reads.delete( sock )
      buffs.delete( sock )
      writes.delete( sock )
      timestamps.delete( sock )
      twins.delete( sock )
    end

  end
end
