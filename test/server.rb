require 'json'
require 'socket'

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
server.listen(512)
reads << server
roles[server] = :server

loop do
  puts "select #{reads.size}"
  rs, _ = IO.select(reads)

  rs.each do |sock|
    role = roles[sock]

    case role
    when :server
      client, addrinfo = sock.accept
      puts "<<< #{addrinfo.inspect}"
      reads << client
      roles[client] = :client
    when :client
      begin
        data = sock.read_nonblock(65535)
      rescue Exception => e
        puts "<<< #{e.class}"
        sock.close
        reads.delete(sock)
        roles.delete(sock)
        next
      end

      puts "<<< #{data.inspect}"
      data2 = 'ok'
      puts ">>> #{data2}"
      sock.write(data2)
    end
  end
end
