require 'json'
require 'socket'

if %w[darwin linux].any?{|plat| RUBY_PLATFORM.include?(plat)}
  Process.setrlimit(:NOFILE, 2048)
  puts "NOFILE #{Process.getrlimit(:NOFILE).inspect}" 
end

config_path = File.expand_path('../test.conf.json', __FILE__)
config = JSON.parse(IO.binread(config_path), symbolize_names: true)
puts config.inspect

redir_host = config[:redir_host]
redir_port = config[:redir_port]
redir_addr = Socket.sockaddr_in(redir_port, redir_host)

reads = []
ecount = 0

2000.times do |i|
  print " #{i}"
  client = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
  client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

  begin
    client.connect_nonblock(redir_addr)
  rescue IO::WaitWritable
  end

  reads << client
end

loop do
  if reads.empty?
    puts
    break
  end

  print " s#{reads.size}"
  rs, _ = IO.select(reads)

  rs.each do |sock|
    begin
      data = sock.read_nonblock(65535)
      puts "<<< #{data.inspect}"
    rescue Exception => e
      ecount += 1
      print " e#{ecount}"
      sock.close
      reads.delete(sock)
    end
  end
end
