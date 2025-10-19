require 'json'
require 'socket'

config_path = File.expand_path('../test.conf.json', __FILE__)
config = JSON.parse(IO.binread(config_path), symbolize_names: true)
puts config.inspect

server_host = config[:server_host]
server_port = config[:server_port]
redir_host = config[:redir_host]
redir_port = config[:redir_port]
redir_addr = Socket.sockaddr_in(redir_port, redir_host)

data = <<EOF
CONNECT #{server_host}:#{server_port} HTTP/1.1
Host: #{server_host}:#{server_port}
Proxy-Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36
EOF

reads = []

client = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
client.connect(redir_addr)
puts ">>> #{data.inspect}"
client.write(data)
reads << client

loop do
  break if reads.empty?
  puts "select #{reads.size}"
  rs, _ = IO.select(reads)

  rs.each do |sock|
    begin
      data = sock.read_nonblock(65535)

      puts "<<< #{data.inspect}"

      if data == "HTTP/1.1 200 OK\r\n\r\n"
        data2 = "lala"
        puts ">>> #{data2}"
        sock.write(data2)
      elsif data == 'ok'
        sock.close
        reads.delete(sock)
      end
    rescue Exception => e
      puts "<<< #{e.class}"
      sock.close
      reads.delete(sock)
    end
  end
end
