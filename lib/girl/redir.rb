require 'girl/hex'
require 'ipaddr'
require 'socket'

module Girl
  class Redir
    MASK = 'MDAVEDUUOFNIUNA-UPERGX0KLBCMMWVEDWUZDICY'

    def initialize(host, port, relay_host, relay_port, hex_block)
      @relay_sockaddr = Socket.sockaddr_in(relay_port, relay_host)

      Girl::Hex.class_eval(hex_block)
      @hex = Girl::Hex.new(MASK)

      redir = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      redir.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      redir.bind(Socket.pack_sockaddr_in(port, host))
      redir.listen(64)
      puts "Listening on #{host}:#{port}"

      @reads = { redir => [ :redir, nil ] }
      @buffs = {}
      @writes = {}
    end

    def run
      loop do
        read_ios, write_ios, errors = IO.select(@reads.keys, @writes.keys)

        read_ios.each do |sock|
          role, twin = @reads[sock]
          case role
          when :redir
            accept(sock)
          when :source
            read_source(sock)
          when :relay
            read_relay(sock)
          end
        end

        write_ios.each do |sock|
          write(sock)
        end
      end
    end

    private

    def accept(redir)
      source, info = redir.accept_nonblock
      @reads[source] = [ :source, nil ]
      @buffs[source] = ''

      print "#{info.ip_unpack.join(':')} r#{@reads.size} w#{@writes.size} #{Time.new} "
    end

    def read_source(source)
      begin
        data = source.read_nonblock(16384)
      rescue EOFError => e
        close(source)
        return
      rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
        puts "read source #{e.class}"
        close(source, false)
        return
      end

      relay = @reads[source][1]

      unless relay
        begin
          dst_addr = source.getsockopt(Socket::SOL_IP, 80) # SO_ORIGINAL_DST https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
        rescue Errno::ENOENT => e
          puts 'ENOENT'
          close(source, false)
          return
        end

        dst_family, dst_port, dst_host = dst_addr.unpack("nnN")
        data, domain = @hex.peek_domain(data, dst_host, dst_port)
        puts "> #{domain} #{IPAddr.new(dst_host, Socket::AF_INET).to_s}:#{dst_port}"

        relay = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)

        begin
          relay.connect_nonblock(@relay_sockaddr)
        rescue IO::WaitWritable
          @reads[relay] = [ :relay, source ]
          @reads[source][1] = relay
          @buffs[relay] = @hex.swap(data)
          @writes[relay] = :ready
          return
        rescue Errno::EISCONN => e
          puts "time cross?"
        rescue Errno::EFAULT, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
          puts "connecting relay #{e.class}"
          close(source, false)
          return
        end
      end

      if relay.closed? # read relay earlier and closed this run
        puts 'relay already closed'
        close(source, false)
        return
      end

      @buffs[relay] << @hex.swap(data)
      @writes[relay] = :ready
    end

    def read_relay(relay)
      begin
        data = relay.read_nonblock(16384)
      rescue EOFError => e
        close(relay)
        return
      rescue IOError, Errno::ECONNRESET, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
        puts "read relay #{e.class}"
        close(relay, false)
        return
      end

      source = @reads[relay][1]

      if source.closed? # read source earlier and closed this run
        puts 'source already closed'
        close(relay, false)
        return
      end

      @buffs[source] << @hex.swap(data)
      @writes[source] = :ready
    end

    def write(sock)
      if sock.closed? # read sock earlier and closed this run
        puts 'sock already closed'
        return
      end

      buff = @buffs[sock]
      unless buff.empty?
        written = 0
        loop do
          left = buff[written..-1]
          begin
            written += sock.write_nonblock(left)
          rescue IO::WaitWritable
            print ' w'
            @buffs[sock] = left
            return
          rescue Errno::ECONNRESET, IOError, Errno::EFAULT, Errno::ETIMEDOUT, Errno::EINVAL, Errno::EPIPE, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENOENT => e
            puts "write #{e.class}"
            close(sock, false)
            return
          end
          break if written >= buff.size
        end
      end

      last_stamp = @writes[sock]
      if last_stamp == :ready
        @buffs[sock] = ''
        @writes.delete(sock)
        return
      end

      close(sock, last_stamp == :twin_eof)
    end

    def close(sock, is_eof = true)
      unless sock.closed?
        sock.setsockopt(Socket::Option.linger(true, 0)) unless is_eof
        sock.close
      end
      role, twin = @reads.delete(sock)
      @buffs.delete(sock)
      @writes.delete(sock)
      if twin
        if @writes[twin] # close twin after she flush buff this run
          @writes[twin] = is_eof ? :twin_eof : :twin_err
        else
          unless twin.closed?
            twin.setsockopt(Socket::Option.linger(true, 0)) unless is_eof
            twin.close
          end
          @reads.delete(twin)
          @buffs.delete(twin)
          @writes.delete(twin)
        end
      end
    end

  end
end
