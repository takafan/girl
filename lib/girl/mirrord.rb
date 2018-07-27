require 'socket'

module Girl
  class Mirrord

    def initialize(mirrord_port, appd_port, is_local = true)
      mirrord = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      mirrord.bind(Socket.pack_sockaddr_in(mirrord_port, '0.0.0.0'))
      mirrord.listen(5)

      puts "mirrord listening on #{mirrord_port}"

      appd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      appd.bind(Socket.pack_sockaddr_in(appd_port, is_local ? '127.0.0.1' : '0.0.0.0'))
      appd.listen(5)

      puts "appd listening on #{appd_port}"

      reads = {
        mirrord => :mirrord, # :appd / :mirrord / :app / :mirror
        appd => :appd
      }
      buffs = {
        mirrord => '',
        appd => ''
      }
      writes = {} # sock => role
      twins = {} # sock => relay_to_sock
      close_after_writes = {} # sock => exception

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :mirrord
            begin
              mirror, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              next
            end

            if reads.any?{|_sock, _role| _role == :mirror }
              mirror.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
              mirror.close
              next
            end

            reads[mirror] = :mirror
            buffs[mirror] = ''
          when :appd
            begin
              app, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              next
            end

            if reads.any?{|_sock, _role| _role == :app }
              app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
              app.close
              next
            end

            mirror, _ = reads.find{|_sock, _role| _role == :mirror }

            unless mirror
              app.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
              app.close
              next
            end

            reads[app] = :app
            buffs[app] = ''
            twins[app] = mirror
            twins[mirror] = app
          when :mirror
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitWritable
              next
            rescue Exception => e
              deal_reading_exception(sock, reads, buffs, writes, twins, readable_socks, writable_socks, close_after_writes, e)
              next
            end

            app = twins[sock]
            buffs[app] << data
            writes[app] = :app
          when :app
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitWritable
              next
            rescue Exception => e
              deal_reading_exception(sock, reads, buffs, writes, twins, readable_socks, writable_socks, close_after_writes, e)
              next
            end

            mirror = twins[sock]
            buffs[mirror] << data
            writes[mirror] = :mirror
          end
        end

        writable_socks.each do |sock|
          buff = buffs[sock]

          begin
            written = sock.write_nonblock(buff)
          rescue IO::WaitWritable
            next
          rescue Exception => e
            close_socket(sock, reads, buffs, writes, twins)
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

    def deal_reading_exception(sock, reads, buffs, writes, twins, readable_socks, writable_socks, close_after_writes, e)
      writable_socks.delete(sock)
      twin = close_socket(sock, reads, buffs, writes, twins)

      if twin
        readable_socks.delete(twin)

        if writable_socks.include?(twin)
          close_after_writes[twin] = e
        else
          twin.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
          close_socket(twin, reads, buffs, writes, twins)
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
