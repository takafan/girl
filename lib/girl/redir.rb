require 'girl/hex'
require 'socket'

module Girl
  class Redir

    def initialize(port, relay_host, relay_port, hex_block = nil)
      relay_sockaddr = Socket.sockaddr_in(relay_port, relay_host)

      if hex_block
        Girl::Hex.class_eval(hex_block)
      end

      hex = Girl::Hex.new
      redir = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      redir.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      redir.bind(Socket.pack_sockaddr_in(port, '0.0.0.0'))
      redir.listen(128)
      puts "#{Process.pid} Listening on #{port}"

      reads = {
        redir => {
          role: :redir
        }
      }
      buffs = {}
      writes = {}

      loop do
        rs, ws = IO.select(reads.keys, writes.keys)

        rs.each do |sock|
          if sock.closed?
            puts 'rs already closed?'
            next
          end

          case reads[sock][:role]
          when :redir
            source, addr = sock.accept_nonblock
            print "p#{Process.pid} #{Time.new} "

            reads[source] = {
              role: :source,
              twin: nil
            }
            buffs[source] = ''
          when :source
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError => e
              deal_exception(e, sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read source #{e.message}"
              deal_exception(e, sock, reads, buffs, writes)
              next
            end

            twin = reads[sock][:twin]

            unless twin
              begin
                dst_addr = sock.getsockopt(Socket::SOL_IP, 80) # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              rescue Errno::ENOENT => e
                puts "get SO_ORIGINAL_DST #{e.message}"
                deal_exception(e, sock, reads, buffs, writes)
                next
              end

              dst_family, dst_port, dst_host = dst_addr.unpack("nnN")
              data = hex.mix(data, dst_host, dst_port)
              twin = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              twin.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)

              begin
                twin.connect_nonblock(relay_sockaddr)
              rescue IO::WaitWritable
                reads[sock][:twin] = twin
                reads[twin] = {
                  role: :relay,
                  twin: sock
                }
                buffs[twin] = ''
              rescue Errno::EISCONN => e
                puts "already connected?"
              rescue Errno::EFAULT, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                deal_exception(e, twin, reads, buffs, writes)
                next
              end
            end

            buffs[twin] << hex.swap(data)
            writes[twin] = {
              role: :relay
            }
          when :relay
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError => e
              deal_exception(e, sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read relay #{e.message}"
              deal_exception(e, sock, reads, buffs, writes)
              next
            end

            twin = reads[sock][:twin]
            buffs[twin] << hex.swap(data)
            writes[twin] = {
              role: :source
            }
          end
        end

        ws.each do |sock|
          if sock.closed?
            puts 'ws already closed?'
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
            deal_exception(e, sock, reads, buffs, writes)
            next
          end

          buffs[sock] = buff[written..-1]
          unless buffs[sock].empty?
            print ' .'
            next
          end

          e = writes.delete(sock)[:twin_exception]
          if e
            sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
            sock.close
            reads.delete(sock)
            buffs.delete(sock)
          end
        end
      end
    end

    private

    def deal_exception(e, sock, reads, buffs, writes)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
      sock.close
      twin = reads.delete(sock).delete(:twin)
      buffs.delete(sock)
      writes.delete(sock)

      if twin && !twin.closed?
        if writes.include?(twin)
          writes[twin][:twin_exception] = e
        else
          twin.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii")) unless e.is_a?(EOFError)
          twin.close
          reads.delete(twin)
          buffs.delete(twin)
          writes.delete(twin)
        end
      end
    end

  end
end
