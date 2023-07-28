require 'json'
require 'socket'

=begin

pc - pi，看掉包

netstat -s | grep "SYNs to LISTEN"

1000个连接 BACKLOG 128：1.5s（掉300个SYN）
1000个连接 BACKLOG 512: 0.7s（不掉包） 1.4s（掉30个SYN）
2000个连接 BACKLOG 512：3.8s（掉900个SYN）

=end

conn_count = ARGV[ 0 ] ? ARGV[ 0 ].to_i : 1000
puts "conn_count #{ conn_count }"

RLIMIT = 1024

if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
  Process.setrlimit( :NOFILE, RLIMIT )
  puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
end

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect
server_host = config[ :server_host ]
server_port = config[ :server_port ]
server_addr = Socket.sockaddr_in( server_port, server_host )

reads = []
writes = []
t0 = Time.new

conn_count.times do | i |
  print " #{ i }"
  client = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
  client.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

  begin
    client.connect_nonblock( server_addr )
  rescue IO::WaitWritable
  end
  
  reads << client
  writes << client
end

puts "reads.size #{ reads.size }"
rcount = 0
eof_count = 0
err_count = 0

loop do
  if reads.size + writes.size == 0 then
    puts
    break
  end

  print " s#{ reads.size }+#{ writes.size }"
  rs, ws, es = IO.select( reads, writes )

  rs.each do | sock |
    begin
      data = sock.read_nonblock( 65535 )
      rcount += 1
      print " #{ rcount }"

      if rcount == conn_count then
        puts " all responsed r#{ rcount } #{ Time.new - t0 }s"
      end
    rescue Exception => e
      if e.is_a?( EOFError ) then
        eof_count += 1
        print " eof#{ eof_count }"
      else
        err_count += 1
        print " #{ e.class } err#{ err_count }"
      end

      sock.close
      reads.delete( sock )

      if err_count + rcount == conn_count then
        puts " all read r#{ rcount } eof#{ eof_count } err#{ err_count } #{ Time.new - t0 }s"
      end
    end
  end

  if ws.any? then
    ws.each do | sock |
      data2 = 'lala'
      sock.write_nonblock( data2 )
      writes.delete( sock )
    end

    if writes.empty? then
      puts " all connected #{ Time.new - t0 }s"
    end
  end

  es.each do | sock |
    puts " select error ??? "
  end
end
