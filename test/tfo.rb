require 'json'
require 'socket'

=begin

sysctl -w net.ipv4.tcp_fastopen=3

ruby tfo.rb 0
connect_nonblock IO::EINPROGRESSWaitWritable
>>> "hello!" 6
<<< "ok"
0.264441993s

ruby tfo.rb 1
#<Socket::Option: INET TCP FASTOPEN "\x05\x00\x00\x00">
read_nonblock Errno::ENOTCONN
>>> "hello!" 6
<<< "ok"
0.130467312s

=end

t0 = Time.new
config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect
server_host = config[ :server_host ]
server_port = config[ :server_port ]
tfod_addr = Socket.sockaddr_in( server_port, server_host )

reads = []
writes = []

tfo = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
tfo.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
is_fastopen = ARGV[ 0 ] == '0' ? false : true

if RUBY_PLATFORM.include?( 'linux' ) then
  tfo.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
end

if is_fastopen then
  tfo.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 )
  puts tfo.getsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN ).inspect
else
  begin
    tfo.connect_nonblock( tfod_addr )
  rescue IO::WaitWritable => e
    puts "connect_nonblock #{ e.class }"
  end
end

reads << tfo
writes << tfo

loop do
  break if reads.empty? && writes.empty?
  rs, ws = IO.select( reads, writes )

  rs.each do | sock |
    begin
      data = sock.read_nonblock( 65535 )
      puts "<<< #{ data.inspect }"
    rescue Errno::ENOTCONN => e
      puts "read_nonblock #{ e.class }"
      next
    rescue Exception => e
      puts "<<< #{ e.class }"
      sock.close
    end

    reads.delete( sock )
  end

  ws.each do | sock |
    data = 'hello!'
    
    begin
      written = sock.sendmsg_nonblock( data, 536870912, tfod_addr )
    rescue Exception => e
      puts "sendmsg_nonblock #{ e.class }"
      sock.close
    end

    puts ">>> #{ data.inspect } #{ written }"
    writes.delete( sock )
  end
end

puts "#{ Time.new - t0 }s"
