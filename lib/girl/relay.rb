require 'girl/xeh'
require 'socket'

module Girl
  class Relay

    def initialize(port, xeh_block = nil)
      if xeh_block
        Girl::Xeh.class_eval(xeh_block)
      end

      xeh = Girl::Xeh.new
      relay = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      relay.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)
      relay.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      relay.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      relay.bind(Socket.pack_sockaddr_in(port, '0.0.0.0'))
      relay.listen(128) # cat /proc/sys/net/ipv4/tcp_max_syn_backlog
      puts "#{Process.pid} Listening on #{port}"

      reads = {
        relay => {
          role: :relay
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
          when :relay
            redir, addr = sock.accept_nonblock
            print "p#{Process.pid} #{Time.new} "

            reads[redir] = {
              role: :redir,
              addr: addr,
              twin: nil
            }
            buffs[redir] = ''
          when :redir
            begin
              data = xeh.swap(sock.read_nonblock(4096))
            rescue EOFError => e
              deal_exception(e, sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read redir #{e.message}"
              deal_exception(e, sock, reads, buffs, writes)
              next
            end

            twin = reads[sock][:twin]

            unless twin
              ret = xeh.decode(data, reads[sock][:addr])
              unless ret[:success]
                puts ret[:error]
                sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                sock.close
                reads.delete(sock)
                buffs.delete(sock)
              end

              data, dst_host, dst_port = ret[:data]
              twin = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              twin.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1)

              begin
                twin.connect_nonblock(Socket.sockaddr_in(dst_port, dst_host))
              rescue IO::WaitWritable
                reads[sock][:twin] = twin
                reads[twin] = {
                  role: :dest,
                  twin: sock
                }
                buffs[twin] = ''
              rescue Errno::EISCONN => e
                puts "time cross?"
              rescue Errno::EFAULT, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                puts "connecting dest #{e.message}"
                deal_exception(e, twin, reads, buffs, writes)
                next
              end
            end

            buffs[twin] << data
            writes[twin] = {
              role: :dest
            }
          when :dest
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError => e
              deal_exception(e, sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read dest #{e.message}"
              deal_exception(e, sock, reads, buffs, writes)
              next
            end

            twin = reads[sock][:twin]
            buffs[twin] << xeh.swap(data)
            writes[twin] = {
              role: :redir
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
