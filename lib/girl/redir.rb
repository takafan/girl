require 'girl/hex'
require 'socket'

module Girl
  class Redir

    def initialize(host, port, relay_host, relay_port, hex_block = nil)
      @relay_sockaddr = Socket.sockaddr_in(relay_port, relay_host)

      if hex_block
        Girl::Hex.class_eval(hex_block)
      end

      @hex = Girl::Hex.new

      redir = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      redir.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      redir.bind(Socket.pack_sockaddr_in(port, host))
      redir.listen(128)
      puts "#{Process.pid} Listening on #{host}:#{port}"

      @thrs = []

      loop do
        rs, ws = IO.select([ redir ])
        select(*rs.first.accept_nonblock)
      end
    end

    private

    def select(client, info)
      @thrs << Thread.new do
        print "#{Process.pid} t#{@thrs.size} #{info.ip_unpack.join(':')} #{Time.new} "

        reads = {
          client => {
            role: :source,
            twin: nil
          }
        }

        buffs = {
          client => ''
        }

        writes = {}

        loop do
          rs, ws = IO.select(reads.keys, writes.keys)

          ws.each do |sock|
            if sock.closed?
              next
            end

            buff = buffs[sock]

            begin
              written = sock.write_nonblock(buff)
            rescue IO::WaitWritable
              print ' w'
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "write #{writes[sock][:role]} #{e.message}"
              close(sock, writes[sock][:twin], false)
            end

            buffs[sock] = buff[written..-1]
            unless buffs[sock].empty?
              next
            end

            writes.delete(sock)
          end

          rs.each do |sock|
            if sock.closed?
              next
            end

            case reads[sock][:role]
            when :source
              relay = reads[sock][:twin]

              begin
                data = sock.read_nonblock(4096)
              rescue EOFError => e
                close(sock, relay)
              rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                puts "read source #{e.message}"
                close(sock, relay, false)
              end

              unless relay
                begin
                  dst_addr = sock.getsockopt(Socket::SOL_IP, 80) # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
                rescue Errno::ENOENT => e
                  puts "get SO_ORIGINAL_DST #{e.message}"
                  close(sock, relay, false)
                end

                dst_family, dst_port, dst_host = dst_addr.unpack("nnN")
                data = @hex.mix(data, dst_host, dst_port)

                relay = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
                relay.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)

                begin
                  relay.connect_nonblock(@relay_sockaddr)
                rescue IO::WaitWritable
                  reads[sock][:twin] = relay
                  reads[relay] = {
                    role: :relay,
                    twin: sock
                  }

                  buffs[relay] = ''
                rescue Errno::EISCONN => e
                  puts "time cross?"
                rescue Errno::EFAULT, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                  puts "connecting relay #{e.message}"
                  close(relay, sock, false)
                end
              end

              buffs[relay] << @hex.swap(data)
              writes[relay] = {
                role: :relay,
                twin: sock
              }
            when :relay
              source = reads[sock][:twin]

              begin
                data = sock.read_nonblock(4096)
              rescue EOFError => e
                close(sock, source)
              rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                puts "read relay #{e.message}"
                close(sock, source, false)
              end

              buffs[source] << @hex.swap(data)
              writes[source] = {
                role: :source,
                twin: sock
              }
            end
          end
        end
      end
    end

    def close(sock, twin, is_eof = true)
      sock.setsockopt(Socket::Option.linger(true, 0)) unless is_eof;
      sock.close

      if twin && !twin.closed?
        twin.setsockopt(Socket::Option.linger(true, 0)) unless is_eof;
        twin.close
      end

      @thrs.delete(Thread.current).exit
    end

  end
end
