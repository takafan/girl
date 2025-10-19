require 'json'
require 'socket'

=begin

ulimit -n
1024

cat /proc/sys/net/ipv4/tcp_max_syn_backlog
128

cat /proc/sys/net/core/somaxconn
4096

cat /proc/sys/net/core/netdev_max_backlog
1000

ss -lt
netstat -s | grep "SYNs to LISTEN"

=end

BACKLOG = 512
RLIMIT = 1024

puts "BACKLOG #{BACKLOG} RLIMIT #{RLIMIT}"

if %w[darwin linux].any?{|plat| RUBY_PLATFORM.include?(plat)}
  Process.setrlimit(:NOFILE, RLIMIT)
  puts "NOFILE #{Process.getrlimit(:NOFILE).inspect}" 
end

config_path = File.expand_path('../test.conf.json', __FILE__)
config = JSON.parse(IO.binread(config_path), symbolize_names: true)
puts config.inspect

server_port = config[:server_port]
reads = []
roles = {}

server = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
server.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
server.bind(Socket.sockaddr_in(server_port, '0.0.0.0'))
server.listen(BACKLOG)
reads << server
roles[server] = :server
rcount = 0
ecount = 0

loop do
  print " s#{reads.size}"
  rs, _, es = IO.select(reads)

  rs.each do |sock|
    role = roles[sock]

    case role
    when :server
      client, addrinfo = sock.accept_nonblock
      reads << client
      roles[client] = :client
      print " a#{reads.size}"
    when :client
      begin
        data = sock.read_nonblock(65535)
        rcount += 1
        print " #{rcount}"

        data2 = "ok"
        sock.write_nonblock(data2)
      rescue Exception => e
        ecount += 1
        print " e#{ecount}"
        sock.close
        reads.delete(sock)
        roles.delete(sock)
      end

    end
  end

  es.each do |sock|
    puts " select error ??? "
  end

  break if reads.empty?
end
