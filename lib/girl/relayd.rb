require 'girl/xeh'
require 'socket'

module Girl
  class Relayd

    def initialize(port, xeh_block = nil)
      Girl::Xeh.class_eval(xeh_block) if xeh_block
      xeh = Girl::Xeh.new
      relayd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      relayd.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
      relayd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      relayd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      relayd.bind(Socket.pack_sockaddr_in(port, '0.0.0.0'))
      relayd.listen(128) # cat /proc/sys/net/ipv4/tcp_max_syn_backlog

      puts "p#{Process.pid} listening on #{port}"

      reads = {
        relayd => :relayd # :relayd / :relay / :dest
      }
      buffs = {} # sock => ''
      writes = {} # sock => :relay / :dest
      twins = {} # relay <=> dest
      close_after_writes = {} # sock => exception
      addrs = {} # sock => addrinfo

      loop do
        readable_socks, writable_socks = IO.select(reads.keys, writes.keys)

        readable_socks.each do |sock|
          case reads[sock]
          when :relayd
            print "p#{Process.pid} #{Time.new} "

            begin
              relay, addr = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR => e
              next
            end

            reads[relay] = :relay
            buffs[relay] = ''
            addrs[relay] = addr
          when :relay
            begin
              data = xeh.swap(sock.read_nonblock(4096))
            rescue IO::WaitReadable
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              next
            end

            dest = twins[sock]

            unless dest
              ret = xeh.decode(data, addrs.delete(sock))
              unless ret[:success]
                puts ret[:error]
                sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
                close_socket(sock, reads, buffs, writes, twins)
                next
              end

              data, dst_host, dst_port = ret[:data]
              dest = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
              dest.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, 1) if RUBY_PLATFORM.include?('linux')
              reads[dest] = :dest
              buffs[dest] = ''
              twins[dest] = sock
              twins[sock] = dest

              begin
                dest.connect_nonblock(Socket.sockaddr_in(dst_port, dst_host))
              rescue IO::WaitWritable
              rescue Exception => e
                deal_io_exception(dest, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
                next
              end

              if data.empty?
                next
              end
            end

            buffs[dest] << data
            writes[dest] = :dest
          when :dest
            begin
              data = sock.read_nonblock(4096)
            rescue IO::WaitReadable
              next
            rescue Exception => e
              deal_io_exception(sock, reads, buffs, writes, twins, close_after_writes, e, readable_socks, writable_socks)
              next
            end

            relay = twins[sock]
            buffs[relay] << xeh.swap(data)
            writes[relay] = :relay
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
