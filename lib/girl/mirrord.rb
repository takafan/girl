require 'socket'

module Girl
  class Mirrord

    def initialize(roomd_port = 6060, appd_host = '127.0.0.1', appd_port_begin = 6061, mirrd_port_begin = 9091, appd_port_limit = 100, mirrd_port_limit = 10000)
      roomd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      roomd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
      roomd.bind(Socket.pack_sockaddr_in(roomd_port, '0.0.0.0'))
      roomd.listen(5)
      puts "roomd listening on #{roomd_port}"

      reads = {
        roomd => :roomd # :roomd / :appd / :room / :app / :mirrd
      }
      buffs = {} # sock => ''
      writes = {} # sock => :room / :app / :mirrd
      twins = {} # app11 <=> mirrd11 / appd1 <=> room1
      close_after_writes = {} # sock => exception
      appd_apps = {} # appd1 => apps
      appd_mirrds = {} # appd1 => mirrds
      appd_ports = {} # appd1 => port1
      mirrd_ports = {} # mirrd1 => port1
      appd_ports_can = (appd_port_begin..(appd_port_begin + appd_port_limit)).to_a
      mirrd_ports_can = (mirrd_port_begin..(mirrd_port_begin + mirrd_port_limit)).to_a

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :roomd
            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts e.class
              next
            end

            reads[room] = :room
            buffs[room] = ''

            appd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            appd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

            begin
              appd_port = appd_ports_can.shift
              unless appd_port
                puts 'too many appds'
                room.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                room.close
                next
              end
              appd.bind(Socket.pack_sockaddr_in(appd_port, appd_host))
            rescue Errno::EADDRINUSE => e
              puts "appd port #{appd_port} #{e.class}, try next"
              retry
            end

            appd.listen(5)
            puts "appd listening on #{appd_host}:#{appd_port} of room #{addr.ip_unpack.join(':')}"

            reads[appd] = :appd
            buffs[appd] = ''
            twins[appd] = room
            twins[room] = appd
            appd_apps[appd] = []
            appd_mirrds[appd] = []
            appd_ports[appd] = appd_port
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts e.class
              next
            end

            reads[app] = :app
            buffs[app] = ''
            room = twins[sock]

            mirrd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            mirrd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

            begin
              mirrd_port = mirrd_ports_can.shift
              unless mirrd_port
                puts 'too many mirrds'
                app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                app.close
                next
              end

              mirrd.bind(Socket.pack_sockaddr_in(mirrd_port, '0.0.0.0'))
            rescue Errno::EADDRINUSE => e
              puts "mirrd port #{mirrd_port} #{e.class}, try next"
              retry
            end

            begin
              mirrd.connect_nonblock(room.remote_address) # p2p
            rescue IO::WaitWritable
              reads[mirrd] = :mirrd
              buffs[mirrd] = ''
            rescue Exception => e
              deal_io_exception(mirrd, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              next
            end

            twins[mirrd] = app
            twins[app] = mirrd
            buffs[room] = "#{mirrd_port};"
            writes[room] = :room
            appd_apps[sock] << app
            appd_mirrds[sock] << mirrd
            mirrd_ports[mirrd] = mirrd_port
          when :room
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            rescue Exception => e
              appd = twins[sock]
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)

              if appd
                appd_ports_can << appd_ports.delete(appd)

                appd_apps.delete(appd).each do |app|
                  app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                  close_socket(app, reads, buffs, writes, twins)
                end

                appd_mirrds.delete(appd).each do |mirrd|
                  mirrd.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                  close_socket(mirrd, reads, buffs, writes, twins)
                end
              end

              next
            end
          when :app
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            rescue Exception => e
              mirrd = twins[sock]
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)

              if mirrd
                mirrd_ports_can << mirrd_ports.delete(mirrd)
              end

              next
            end

            mirrd = twins[sock]
            buffs[mirrd] << data
            writes[mirrd] = :mirrd
          when :mirrd
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              print ' r'
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              mirrd_ports_can << mirrd_ports.delete(sock)
              next
            end

            app = twins[sock]
            buffs[app] << data
            writes[app] = :app
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
