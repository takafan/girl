##
# usage
# =====
#
# Girl::Mirrord.new(6060, '127.0.0.1', 6061) # server
# Girl::Mirror.new('your.server.ip', 6060, '127.0.0.1', 22) # home
# ssh -p6061 root@127.0.0.1 # server
#
require 'socket'

module Girl

  class Mirror

    def initialize(roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22)
      reads = {}  # sock => :room / :mirr / :app
      buffs = {} # sock => ''
      writes = {} # sock => :mirr / :app
      twins = {} # mirr <=> app
      close_after_writes = {} # sock => exception
      appd_sockaddr = Socket.sockaddr_in(appd_port, appd_host)

      room = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      room.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      room.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      room.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

      begin
        puts "connect roomd #{roomd_host}:#{roomd_port}"
        room.connect_nonblock(Socket.sockaddr_in(roomd_port, roomd_host))
      rescue IO::WaitWritable
        reads[room] = :room
      end

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :room
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            end

            data.split(';').map{|s| s.to_i}.each do |mirrd_port|
              mirr = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              mirr.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
              mirr.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
              mirr.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
              mirr.bind(room.local_address)

              begin
                mirr.connect_nonblock(Socket.sockaddr_in(mirrd_port, roomd_host)) # p2p
              rescue IO::WaitWritable
                reads[mirr] = :mirr
                buffs[mirr] = ''
              end

              app = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              app.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
              app.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
              app.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

              begin
                app.connect_nonblock(appd_sockaddr)
              rescue IO::WaitWritable
                reads[app] = :app
                buffs[app] = ''
              end

              twins[app] = mirr
              twins[mirr] = app
            end
          when :mirr
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              next
            end

            app = twins[sock]
            buffs[app] << data
            writes[app] = :app
          when :app
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              next
            end

            mirr = twins[sock]
            buffs[mirr] << data
            writes[mirr] = :mirr
          end
        end

        writable_socks.each do |sock|
          buff = buffs[sock]

          begin
            written = sock.write_nonblock(buff)
          rescue IO::WaitWritable
            print ' c' # connecting
            next
          rescue Exception => e
            deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
            next
          end

          buffs[sock] = buff[written..-1]

          unless buffs[sock].empty?
            next
          end

          e = close_after_writes.delete(sock)

          if e
            sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
            close_socket(sock, reads, buffs, writes, twins)
            next
          end

          writes.delete(sock)
        end
      end
    end

    private

    def deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
      twin = close_socket(sock, reads, buffs, writes, twins)

      if twin
        if writes.include?(twin)
          reads.delete(twin)
          twins.delete(twin)
          close_after_writes[twin] = e
        else
          twin.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
          close_socket(twin, reads, buffs, writes, twins)
          writable_socks.delete(twin)
        end

        readable_socks.delete(twin)
      end

      writable_socks.delete(sock)
    end

    def close_socket(sock, reads, buffs, writes, twins)
      sock.close
      reads.delete(sock)
      buffs.delete(sock)
      writes.delete(sock)
      twins.delete(sock) # return twin
    end

  end
end
