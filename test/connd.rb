require 'json'
require 'socket'

is_nonblock = ARGV[ 0 ] ? ( ARGV[ 0 ] == "true" ) : true
puts "is_nonblock #{ is_nonblock }"

if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
  Process.setrlimit( :NOFILE, 2048 )
  puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
end

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect

server_port = config[ :server_port ]
reads = []
roles = {}

server = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
server.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
server.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
server.bind( Socket.sockaddr_in( server_port, '0.0.0.0' ) )
server.listen( 5 )
reads << server
roles[ server ] = :server
rcount = 0

loop do
  # puts 'select'
  rs, _ = IO.select( reads )

  rs.each do | sock |
    role = roles[ sock ]

    case role
    when :server
      if is_nonblock then
        client, addrinfo = sock.accept_nonblock
      else
        client, addrinfo = sock.accept
      end
      
      reads << client
      roles[ client ] = :client
      print " a#{ reads.size }"
    when :client
      begin
        data = sock.read_nonblock( 65535 )
        rcount += 1
        print " #{ rcount }"

        # puts "read client #{ data.inspect }"
        # data2 = "ok"
        # puts "write #{ data2 }"
        # sock.write_nonblock( data2 )
        # sock.close
        # reads.delete( sock )
      rescue Exception => e
        puts "read client #{ e.class }"
        sock.close
        reads.delete( sock )
        roles.delete( sock )
      end

    end
  end
end
