require 'socket'

module Girl
  ##
  # usage:
  #
  # server: Girl::Mirrord.new(6000, 2222)
  #
  # home: Girl::Mirror.new('you.r.server.ip', 6000, '127.0.0.1', 22)
  #
  # server: ssh -p2222 root@127.0.0.1
  #
  class Mirror

    def initialize(mirrord_host, mirrord_port, appd_host = '127.0.0.1', appd_port = 22)
      reads = {}  # sock => :mirror / :app
      buffs = {} # sock => ''
      writes = {} # sock => :mirror / :app
      twins = {} # sock => relay_to_sock
      close_after_writes = {} # sock => exception
      mirrord_sockaddr = Socket.sockaddr_in(mirrord_port, mirrord_host)

      puts "connect mirrord for #{appd_host}:#{appd_port}"
      connect_mirrord(mirrord_sockaddr, reads, buffs)

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :mirror
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError, IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              # relaying eof to appd
              deal_reading_exception(sock, reads, buffs, writes, twins, readable_socks, writable_socks, close_after_writes, e)

              # rebridge. if eof was not caused by app but caused by mirrord itself, we'll get Connection refused and exit.
              connect_mirrord(mirrord_sockaddr, reads, buffs)
              next
            end

            app = twins[sock]

            unless app
              app = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              app.connect(Socket.sockaddr_in(appd_port, appd_host))
              reads[app] = :app
              buffs[app] = ''
              twins[app] = sock
              twins[sock] = app
            end

            buffs[app] << data
            writes[app] = :app
          when :app
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError, IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              # relaying eof to mirrord
              deal_reading_exception(sock, reads, buffs, writes, twins, readable_socks, writable_socks, close_after_writes, e)

              # rebridge
              connect_mirrord(mirrord_sockaddr, reads, buffs)
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
          rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
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

    def connect_mirrord(mirrord_sockaddr, reads, buffs)
      sock = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      sock.connect(mirrord_sockaddr)
      reads[sock] = :mirror
      buffs[sock] = ''
      sock
    end

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
