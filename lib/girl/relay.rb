require 'girl/xeh'
require 'socket'

module Girl
  class Relay

    def initialize(host, port, xeh_block)
      Girl::Xeh.class_eval(xeh_block)
      @xeh = Girl::Xeh.new(port)

      relay = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      relay.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      relay.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      relay.bind(Socket.pack_sockaddr_in(port, host))
      relay.listen(128) # cat /proc/sys/net/ipv4/tcp_max_syn_backlog
      puts "#{Process.pid} Listening on #{host}:#{port}"

      @thrs = []

      loop do
        rs, ws = IO.select([ relay ])
        select(*rs.first.accept_nonblock)
      end
    end

    private

    def select(client, info)
      @thrs << Thread.new do
        puts "#{Process.pid} t#{@thrs.size} #{info.ip_unpack.join(':')} #{Time.new}"

        reads = {
          client => {
            role: :redir,
            twin: nil
          }
        }

        buffs = {
          client => ''
        }

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
              close(sock, writes[sock][:twin], false)
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
              dest = reads[sock][:twin]

              begin
                data = @xeh.swap(sock.read_nonblock(4096))
              rescue EOFError => e
                close(sock, dest)
              rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                puts "read redir #{e.message}"
                close(sock, dest, false)
              end

              unless dest
                ret = @xeh.decode(data)
                unless ret[:success]
                  puts ret[:error]
                  close(sock, false)
                end

                data, dst_host, dst_port = ret[:data]
                dest = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        
                begin
                  dest.connect_nonblock(Socket.sockaddr_in(dst_port, dst_host))
                rescue IO::WaitWritable
                  reads[sock][:twin] = dest
                  reads[dest] = {
                    role: :dest,
                    twin: sock
                  }

                  buffs[dest] = ''
                rescue Errno::EISCONN => e
                  puts "time cross?"
                rescue Errno::EFAULT, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                  puts "connecting dest #{e.message}"
                  close(dest, sock, false)
                end
              end

              buffs[dest] << data
              writes[dest] = { 
                role: :dest,
                twin: sock
              }
            when :dest
              redir = reads[sock][:twin]

              begin
                data = sock.read_nonblock(4096)
              rescue EOFError => e
                close(sock, redir)
              rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
                puts "read dest #{e.message}"
                close(sock, redir, false)
              end

              buffs[redir] << @xeh.swap(data)
              writes[redir] = { 
                role: :redir,
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
