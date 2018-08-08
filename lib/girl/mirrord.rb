require 'socket'

module Girl
  class Mirrord

    def initialize(roomd_port = 6060, appd_host = '127.0.0.1', room_limit = 100)
      roomd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      roomd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1) # avoid EADDRINUSE after a restart
      roomd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
      roomd.bind(Socket.pack_sockaddr_in(roomd_port, '0.0.0.0'))
      roomd.listen(5)
      puts "roomd listening on #{roomd_port}"

      reads = {
        roomd => :roomd # :roomd / :appd / :mirrd / :room / :app / :mirr
      }
      buffs = {} # sock => ''
      writes = {} # sock => :room / :app / :mirr
      twins = {} # app11 <=> mirr11
      close_after_writes = {} # sock => exception
      pending_apps = {} # app11 => appd1
      appd_infos = {} # appd1 => { room: room1, mirrd: mirrd1, pending_apps: { app11: '' }, linked_apps: { app12: mirr12 } }
      appd_port_begin = roomd_port + 1
      appd_ports_can = (appd_port_begin...(appd_port_begin + room_limit)).to_a
      mirrd_port_begin = appd_port_begin + room_limit
      mirrd_ports_can = (mirrd_port_begin...(mirrd_port_begin + room_limit)).to_a

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :roomd
            begin
              room, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts "accept a room #{e.class} ?"
              next
            end

            reads[room] = :room
            buffs[room] = ''

            appd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            appd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
            appd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

            begin
              appd_port = appd_ports_can.shift
              unless appd_port
                puts 'no more appd port'
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
            puts "appd listening on #{appd_host}:#{appd_port} of room #{room.local_address.ip_unpack.join(':')}"

            reads[appd] = :appd

            mirrd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            mirrd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
            mirrd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')

            begin
              mirrd_port = mirrd_ports_can.shift
              unless mirrd_port
                puts 'no more mirrd port'
                appd.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                appd.close
                room.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                room.close
                next
              end
              mirrd.bind(Socket.pack_sockaddr_in(mirrd_port, '0.0.0.0'))
            rescue Errno::EADDRINUSE => e
              puts "mirrd port #{mirrd_port} #{e.class}, try next"
              retry
            end

            mirrd.listen(5)
            puts "mirrd listening on #{mirrd_port} of room #{room.local_address.ip_unpack.join(':')}"

            reads[mirrd] = :mirrd

            appd_infos[appd] = {
              room: room,
              mirrd: mirrd,
              pending_apps: {},
              linked_apps: {}
            }
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts "accept a app #{e.class} ?"
              next
            end

            appd_info = appd_infos[sock]
            room = appd_info[:room]
            mirrd = appd_info[:mirrd]
            reads[app] = :app
            buffs[app] = ''
            pending_apps[app] = sock
            appd_info[:pending_apps][app] = ''
            buffs[room] = "#{mirrd.local_address.ip_unpack.last};"
            writes[room] = :room
          when :mirrd
            begin
              mirr, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              puts "accept a mirr #{e.class} ?"
              next
            end

            appd, appd_info = appd_infos.find{|_appd, _info| _info[:mirrd] == sock }
            app, buff = appd_info[:pending_apps].shift
            unless app
              puts "no more pending apps under appd?"
              next
            end

            reads[mirr] = :mirr
            buffs[mirr] = buff
            writes[mirr] = :mirr unless buff.empty?
            twins[mirr] = app
            twins[app] = mirr
            appd_info[:linked_apps][app] = mirr
          when :room
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, reads[sock], close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos, appd_ports_can, mirrd_ports_can)
              next
            end

            puts "r unexpected room data? #{data.inspect}"
          when :app
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, reads[sock], close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos, appd_ports_can, mirrd_ports_can)
              next
            end

            mirr = twins[sock]
            unless mirr
              appd = pending_apps[sock]
              appd_info = appd_infos[appd]
              appd_info[:pending_apps][sock] << data
              next
            end

            buffs[mirr] << data
            writes[mirr] = :mirr
          when :mirr
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable => e
              puts "r #{reads[sock]} #{e.class} ?"
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, reads[sock], close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos, appd_ports_can, mirrd_ports_can)
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
            next
          rescue Exception => e
            deal_io_exception(sock, reads, buffs, writes, twins, writes[sock], close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos, appd_ports_can, mirrd_ports_can)
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

    def deal_io_exception(sock, reads, buffs, writes, twins, role, close_after_writes, e, readable_socks, writable_socks, pending_apps, appd_infos, appd_ports_can, mirrd_ports_can)
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

      case role
      when :room
        appd, appd_info = appd_infos.find{|_appd, _info| _info[:room] == sock }
        if appd
          appd_port = appd.local_address.ip_unpack.last
          appd.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
          close_socket(appd, reads, buffs, writes, twins)
          appd_ports_can << appd_port

          mirrd = appd_info[:mirrd]
          mirrd_port = mirrd.local_address.ip_unpack.last
          mirrd.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
          close_socket(mirrd, reads, buffs, writes, twins)
          mirrd_ports_can << mirrd_port

          appd_info[:pending_apps].each do |app, buff|
            app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
            close_socket(app, reads, buffs, writes, twins)
            pending_apps.delete(app)
          end

          appd_info[:linked_apps].each do |app, mirr|
            app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
            close_socket(app, reads, buffs, writes, twins)
            pending_apps.delete(app)
            mirr.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
            close_socket(mirr, reads, buffs, writes, twins)
          end

          appd_infos.delete(appd)
        end
      when :app
        appd = pending_apps.delete(sock)
        appd_info = appd_infos[appd]
        appd_info[:pending_apps].delete(sock)
        appd_info[:linked_apps].delete(sock)
      when :mirr
        if twin
          appd = pending_apps.delete(twin)
          appd_info = appd_infos[appd]
          appd_info[:pending_apps].delete(twin)
          appd_info[:linked_apps].delete(twin)
        end
      end
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
