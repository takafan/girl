require 'json'
require 'socket'

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect

proxyd_host = config[ :relay_proxyd_host ]
girl_port = config[ :relay_girl_port ]
im = config[ :im ] || 'whoami'
girl_addr = Socket.sockaddr_in( girl_port, proxyd_host )

reads = []
t0 = Time.new
ecount = 0
girlc = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
girlc.sendmsg( im.reverse, 0, girl_addr )

1018.times do | i |
  print " #{ i }"
  client = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
  client.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

  begin
    client.connect_nonblock( girl_addr )
  rescue IO::WaitWritable
  end

  reads << client
end

loop do
  if reads.empty? then
    puts
    break
  end

  print " s#{ reads.size }"
  rs, _ = IO.select( reads )

  rs.each do | sock |
    begin
      data = sock.read_nonblock( 65535 )
      puts "<<< #{ data.inspect }"
    rescue Exception => e
      ecount += 1
      print " e#{ ecount }"
      sock.close
      reads.delete( sock )
    end
  end
end
