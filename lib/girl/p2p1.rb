require 'socket'

module Girl
  class P2p1

    def initialize( roomd_host, roomd_port, appd_host, appd_port, timeout = 1800, room_title = nil )
      reads = {}  # sock => :room / :p1 / :app
      buffs = {} # sock => ''
      writes = {} # sock => :room / :p1 / :app
      twins = {} # p1 <=> app
      roomd_sockaddr = Socket.sockaddr_in( roomd_port, roomd_host )
      connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
      appd_sockaddr = Socket.sockaddr_in( appd_port, appd_host )
      reconn = 0

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys, [], timeout )

        unless readable_socks
          puts "flash #{ Time.new }"
          connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
          next
        end

        readable_socks.each do | sock |
          case reads[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
              reconn = 0
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ETIMEDOUT => e
              if e.is_a?( EOFError )
                reconn = 0
              elsif reconn > 100
                raise e
              else
                reconn += 1
              end

              sleep 5
              puts "#{ e.class }, reconn #{ reconn }"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )

              break
            end

            if reads.find{ | _, role | role == :p1 }
              next
            end

            p2_ip, p2_port = data.split( ':' )

            p1 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            p1.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
            p1.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
            p1.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            p1.bind( sock.local_address ) # use the hole
            reads[ p1 ] = :p1
            buffs[ p1 ] = ''

            begin
              p1.connect_nonblock( Socket.sockaddr_in( p2_port, p2_ip ) )
            rescue IO::WaitWritable
            rescue Exception => e
              puts "p2p #{ p2_ip }:#{ p2_port } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
              break
            end
          when :p1
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue Exception => e
              puts "r #{ reads[ sock ] } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
              break
            end

            app = twins[ sock ]

            unless app
              app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              app.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
              reads[ app ] = :app
              buffs[ app ] = ''
              twins[ app ] = sock
              twins[ sock ] = app

              begin
                app.connect_nonblock( appd_sockaddr )
              rescue IO::WaitWritable
              rescue Exception => e
                puts "c appd #{ appd_host }:#{ appd_port } #{ e.class }, flash a room"
                connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
                break
              end
            end

            buffs[ app ] << data
            writes[ app ] = :app
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue Exception => e
              puts "r #{ reads[ sock ] } #{ e.class }, flash a room"
              connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
              break
            end

            p1 = twins[ sock ]
            buffs[ p1 ] << data
            writes[ p1 ] = :p1
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable
            next
          rescue Exception => e
            puts "w #{ writes[ sock ] } #{ e.class }, flash a room"
            connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
            break
          end

          puts "written #{ written }"
          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          writes.delete( sock )
        end
      end
    end

    private

    def connect_roomd( roomd_sockaddr, reads, buffs, writes, twins, room_title )
      reads.keys.each{ | sock | sock.close }
      reads.clear
      buffs.clear
      writes.clear
      twins.clear

      sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      sock.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        puts 'connect roomd'
        sock.connect_nonblock( roomd_sockaddr )
      rescue IO::WaitWritable
        reads[ sock ] = :room

        if room_title
          buffs[ sock ] = "room#{ room_title }".unpack( "C*" ).map{ |c| c.chr }.join
          writes[ sock ] = :room
        end
      end
    end
  end
end
