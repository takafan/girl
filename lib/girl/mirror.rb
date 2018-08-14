##
# usage
# =====
#
# Girl::Mirror.new('your.server.ip', 6060, '127.0.0.1', 22, '周立波') # home
#
# Girl::Mirrord.new(6060, '127.0.0.1') # server
# ls /tmp/mirrord # 45678-周立波
# ssh -p45678 root@localhost
#
require 'socket'

module Girl
  class Mirror

    def initialize(roomd_host, roomd_port, appd_host = '127.0.0.1', appd_port = 22, room_title = nil, timeout = 3600)
      reads = {}  # sock => :room / :mirr / :app
      buffs = {} # sock => ''
      writes = {} # sock => :room / :mirr / :app
      twins = {} # mirr <=> app
      close_after_writes = {} # sock => exception
      roomd_sockaddr = Socket.sockaddr_in(roomd_port, roomd_host)
      connect_roomd(roomd_sockaddr, reads, buffs, writes, room_title)
      appd_sockaddr = Socket.sockaddr_in(appd_port, appd_host)
      reconn = 0

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys, [], timeout)

        unless readable_socks
          puts "reconnect #{Time.new}"
          reads.keys.each{|_sock| _sock.close}
          reads.clear
          buffs.clear
          writes.clear
          twins.clear
          close_after_writes.clear
          connect_roomd(roomd_sockaddr, reads, buffs, writes, room_title)
          next
        end

        readable_socks.each do |sock|
          case reads[sock]
          when :room
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
              next
            rescue EOFError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH => e
              puts "read room #{e.class} #{Time.new}"
              reconn = reconnect_roomd(reconn, e, roomd_sockaddr, reads, buffs, writes, twins, close_after_writes, readable_socks, writable_socks, room_title)
              break
            end

            data.split(';').map{|s| s.to_i}.each do |mirrd_port|
              mirr = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              mirr.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
              mirr.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
              mirr.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
              mirr.bind(sock.local_address)
              app = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              app.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
              reads[mirr] = :mirr
              buffs[mirr] = ''
              reads[app] = :app
              buffs[app] = ''
              twins[app] = mirr
              twins[mirr] = app

              begin
                mirr.connect_nonblock(Socket.sockaddr_in(mirrd_port, roomd_host))
              rescue IO::WaitWritable
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect mirrd #{roomd_host}:#{mirrd_port} #{e.class}"
                deal_io_exception(mirr, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
                next
              end

              begin
                app.connect_nonblock(appd_sockaddr)
              rescue IO::WaitWritable
              rescue Errno::EADDRNOTAVAIL => e
                puts "connect appd #{appd_host}:#{appd_port} #{e.class}"
                deal_io_exception(app, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
                next
              end
            end
          when :mirr
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
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
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
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
            next
          rescue Exception => e
            deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
            next
          end

          buffs[sock] = buff[written..-1]

          unless buffs[sock].empty?
            print ' .'
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

    def reconnect_roomd(reconn, e, roomd_sockaddr, reads, buffs, writes, twins, close_after_writes, readable_socks, writable_socks, room_title)
      if e.is_a?(EOFError)
        reconn = 0
      elsif reconn > 100
        raise e
      else
        reconn += 1
      end

      reads.keys.each{|_sock| _sock.close}
      reads.clear
      buffs.clear
      writes.clear
      twins.clear
      close_after_writes.clear
      readable_socks.clear
      writable_socks.clear
      sleep 5
      print "retry #{reconn}"
      connect_roomd(roomd_sockaddr, reads, buffs, writes, room_title)

      reconn
    end

    def connect_roomd(roomd_sockaddr, reads, buffs, writes, room_title)
      sock = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      sock.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
      reads[sock] = :room

      begin
        puts 'connect roomd'
        sock.connect_nonblock(roomd_sockaddr)
      rescue IO::WaitWritable
        if room_title
          buffs[sock] = room_title.unpack("C*").map{|c| c.chr }.join
          writes[sock] = :room
        end
      end
    end

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
