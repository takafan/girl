require 'girl/hex'
require 'ipaddr'
require 'socket'

module Girl
  class Redir
    MASK = 'MDAVEDUUOFNIUNA-UPERGX0KLBCMMWVEDWUZDICY'

    def initialize(host, port, relay_host, relay_port, hex_block)
      relay_sockaddr = Socket.sockaddr_in(relay_port, relay_host)

      Girl::Hex.class_eval(hex_block)
      hex = Girl::Hex.new(MASK)

      redir = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      redir.bind(Socket.pack_sockaddr_in(port, host))
      redir.listen(64)
      puts "#{Process.pid} Listening on #{host}:#{port}"

      reads = {
        redir => {
          role: :redir
        }
      }

      buffs = {}
      writes = {}

      loop do
        rs, ws = IO.select(reads.keys, writes.keys)

        # write firstly
        ws.each do |sock|
          if sock.closed?
            # already closed by twin's error
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
            close(sock, reads, buffs, writes, false)
            next
          end

          buffs[sock] = buff[written..-1]
          unless buffs[sock].empty?
            next
          end

          writes.delete(sock)
        end

        # read secondly, happy eof
        rs.each do |sock|
          if sock.closed?
            # already closed by write error, or twin's error
            next 
          end

          case reads[sock][:role]
          when :redir
            source, info = sock.accept_nonblock
            print "#{Process.pid} #{info.ip_unpack.join(':')} #{Time.new} "

            reads[source] = {
              role: :source,
              twin: nil
            }
    
            buffs[source] = ''
          when :source
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError => e
              close(sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read source #{e.message}"
              close(sock, reads, buffs, writes, false)
              next
            end

            relay = reads[sock][:twin]

            unless relay
              begin
                dst_addr = sock.getsockopt(Socket::SOL_IP, 80) # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              rescue Errno::ENOENT => e
                puts "get SO_ORIGINAL_DST #{e.message}"
                close(sock, reads, buffs, writes, false)
                next
              end
      
              dst_family, dst_port, dst_host = dst_addr.unpack("nnN")
              data, domain = hex.peek_domain(data, dst_host, dst_port)
              puts "> #{domain} #{IPAddr.new(dst_host, Socket::AF_INET).to_s}:#{dst_port}"
      
              relay = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
    
              begin
                relay.connect_nonblock(relay_sockaddr)
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
                close(relay, reads, buffs, writes, false)
                next
              end
            end
            
            buffs[relay] << hex.swap(data)
            writes[relay] = { 
              role: :relay,
              twin: sock
            }
          when :relay
            begin
              data = sock.read_nonblock(4096)
            rescue EOFError => e
              close(sock, reads, buffs, writes)
              next
            rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
              puts "read relay #{e.message}"
              close(sock, reads, buffs, writes, false)
              next
            end

            source = reads[sock][:twin]
            buffs[source] << hex.swap(data)
            writes[source] = { 
              role: :source,
              twin: sock
            }
          end
        end
      end
    end

    private

    def close(sock, reads, buffs, writes, is_eof = true)
      sock.setsockopt(Socket::Option.linger(true, 0)) unless is_eof;
      sock.close
      twin = reads.delete(sock)[:twin]
      buffs.delete(sock)
      writes.delete(sock)

      if twin && !twin.closed?
        twin.setsockopt(Socket::Option.linger(true, 0)) unless is_eof;
        twin.close
        reads.delete(twin)
        buffs.delete(twin)
        writes.delete(twin)
      end
    end

  end
end
