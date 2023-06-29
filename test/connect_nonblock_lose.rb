require 'json'
require 'socket'

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect

proxy_host = config[ :proxy_host ]
proxy_port = config[ :proxy_port ]
proxy_addr = Socket.sockaddr_in( proxy_port, proxy_host )

reads = []
sock_count = 1000

puts "connect_nonblock #{ sock_count }"

sock_count.times do | i |
  client = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
  client.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
  
  begin
    client.connect_nonblock( proxy_addr )
  rescue IO::WaitWritable
  end

  reads << client
end

rs_count = 0

loop do
  rs, _ = IO.select( reads )

  rs.each do | sock |
    begin
      data = sock.read_nonblock( 65535 )
      puts "read #{ data.inspect }"
    rescue Exception => e
      sock.close
      reads.delete( sock )
    end
  end

  rs_count += rs.size
  print " #{ rs_count }"
  
  if rs_count >= sock_count then
    puts
    break
  end
end
