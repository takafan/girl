require 'json'
require 'socket'

=begin

s1 - s2，500个非nonblock连接 0.090201364s
建到1000个连接左右开始变得极慢，1500个连接 33.33498151s

pc - 树莓派（金士顿），500个非nonblock连接 24.7279658s
pc - 树莓派（闪迪），500个非nonblock连接 14.5275723s

nonblock 收不全？队列满？
=end

conn_count = ARGV[ 0 ] ? ARGV[ 0 ].to_i : 500
puts "conn_count #{ conn_count }"
is_nonblock = ARGV[ 1 ] ? ( ARGV[ 1 ] == "true" ) : true
puts "is_nonblock #{ is_nonblock }"

if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
  Process.setrlimit( :NOFILE, 2048 )
  puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
end

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect

server_ip = config[ :server_ip ]
server_port = config[ :server_port ]
server_addr = Socket.sockaddr_in( server_port, server_ip )

reads = []
writes = []
roles = {}

t0 = Time.new

conn_count.times do | i |
  print " #{ i }"
  client = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
  client.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

  if is_nonblock then
    begin
      client.connect_nonblock( server_addr )
    rescue IO::WaitWritable
    end
  else
    client.connect( server_addr )
  end
  
  reads << client
  writes << client
  roles[ client ] = :client
end

puts "reads.size #{ reads.size }"


loop do
  puts 'select'
  rs, ws = IO.select( reads, writes )

  rs.each do | sock |
    role = roles[ sock ]

    case role
    when :client
      begin
        data = sock.read_nonblock( 65535 )
        puts "read client #{ data.inspect } index #{ reads.index( sock ) } reads.size #{ reads.size }"
      rescue Exception => e
        puts "read client #{ e.class }"
        sock.close
        reads.delete( sock )
        roles.delete( sock )
      end
    end
  end

  ws.each do | sock |
    writes.delete( sock )
  end

  if ws.size > 0 && writes.empty? then
    puts "all writable #{ Time.new - t0 }s"

    reads.each do | sock |
      data2 = 'lala'
      # puts "write #{ data2 }"
      sock.write_nonblock( data2 )
    end
  end
end
