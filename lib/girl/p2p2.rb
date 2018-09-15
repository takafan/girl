##
# usage:
#
# 1. Girl::P2pd.new( 6262, '/tmp/p2pd' ) # @server
#
# 2. Girl::P2p1.new( '{ your.server.ip }', 6262, '192.168.1.70', 22, 1800, '周立波' ) # @home.pi
#
# 3. echo "ls -lt" | sftp -q root@{ your.server.ip }:/tmp/p2pd # saw 6.6.6.6:12345-周立波
#
# 4. Girl::P2p2.new( 'your.server.ip', 6262, '6.6.6.6:12345-周立波', '/tmp/p2p2' ) # @company.pi
#
# 5. echo "ls -lt" | sftp -q root@10.17.2.59:/tmp/p2p2 # saw 45678--6.6.6.6:12345-周立波
#
# 6. ssh -p45678 root@10.17.2.59
#
require 'socket'

module Girl
  class P2p2

    def initialize( roomd_host, roomd_port, p1_info, tmp_dir = '/tmp/p2p2' )
      reads = {} # sock => :room / :p2 / :appd / :app
      buffs = {} # sock => ''
      writes = {} # sock => :room / :p2 / :app
      twins = {} # app <=> p2
      connect_p1_after_write = true
      tmp_path = ''
      p1_host, p1_port = p1_info[ 0, p1_info.index( '-' ) ].split( ':' )
      p1_sockaddr = Socket.sockaddr_in( p1_port, p1_host )
      rep2p = 0

      room = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      room.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      room.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      room.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        room.connect_nonblock( Socket.sockaddr_in( roomd_port, roomd_host ) )
      rescue IO::WaitWritable
      end

      reads[ room ] = :room
      buffs[ room ] = "come#{ p1_host }:#{ p1_port }"
      writes[ room ] = :room

      Dir.mkdir( tmp_dir ) unless Dir.exist?( tmp_dir )

      loop do
        readable_socks, writable_socks = IO.select( reads.keys, writes.keys )

        readable_socks.each do | sock |
          case reads[ sock ]
          when :room
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue Exception => e
              begin
                File.delete( tmp_path )
              rescue Errno::ENOENT
              end

              raise e
            end
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts "accept a app #{ e.class } ?"
              next
            end

            if reads.find{ | _, role | role == :app }
              app.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
              app.close
              next
            end

            p2, _ = reads.find{ | _, role | role == :p2 }
            reads[ app ] = :app
            buffs[ app ] = ''
            twins[ app ] = p2
            twins[ p2 ] = app
          when :p2
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue Errno::ECONNREFUSED => e
              if rep2p > 10
                begin
                  File.delete( tmp_path )
                rescue Errno::ENOENT
                end

                raise e
              else
                rep2p += 1
              end

              puts "#{ e.class }, rep2p #{ rep2p }"
              sock.close
              reads.delete( sock )
              buffs.delete( sock )
              sleep 1
              p2p( room, p1_sockaddr, reads, buffs )
              break
            rescue Exception => e
              begin
                File.delete( tmp_path )
              rescue Errno::ENOENT
              end

              raise e
            end

            app = twins[ sock ]
            buffs[ app ] << data
            writes[ app ] = :app
          when :app
            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable => e
              puts "r #{ reads[ sock ] } #{ e.class } ?"
              next
            rescue Exception => e
              begin
                File.delete( tmp_path )
              rescue Errno::ENOENT
              end

              raise e
            end

            p2 = twins[ sock ]
            buffs[ p2 ] << data
            writes[ p2 ] = :p2
          end
        end

        writable_socks.each do | sock |
          buff = buffs[ sock ]

          begin
            written = sock.write_nonblock( buff )
          rescue IO::WaitWritable
            next
          rescue Exception => e
            begin
              File.delete( tmp_path )
            rescue Errno::ENOENT
            end

            raise e
          end

          buffs[ sock ] = buff[ written..-1 ]

          unless buffs[ sock ].empty?
            next
          end

          writes.delete( sock )

          if connect_p1_after_write
            p2p( room, p1_sockaddr, reads, buffs )

            appd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            appd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 ) # avoid EADDRINUSE after a restart
            appd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
            appd.bind( Socket.pack_sockaddr_in( 0, '0.0.0.0' ) )
            appd.listen( 5 )
            puts "appd listening on #{ appd.local_address.ip_unpack.join(':') }"

            reads[ appd ] = :appd
            buffs[ appd ] = ''
            tmp_path = File.join( tmp_dir, "#{ appd.local_address.ip_unpack.last }--#{ p1_info }" )
            File.open( tmp_path, 'w' )

            connect_p1_after_write = false
          end
        end
      end
    end

    private

    def p2p( room, p1_sockaddr, reads, buffs )
      p2 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      p2.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      p2.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      p2.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      p2.bind( room.local_address ) # use the hole

      begin
        puts 'd> p2 connect p1'
        p2.connect_nonblock( p1_sockaddr )
      rescue IO::WaitWritable
      end

      reads[ p2 ] = :p2
      buffs[ p2 ] = ''
    end

  end
end
