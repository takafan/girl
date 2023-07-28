require 'json'
require 'socket'

config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect
server_port = config[ :server_port ]

reads = []
roles = {}

is_fastopen = ARGV[ 0 ] == '0' ? false : true
tfod = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
tfod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
tfod.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

if is_fastopen then
  tfod.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 512 )
  puts tfod.getsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN ).inspect
end

tfod.bind( Socket.sockaddr_in( server_port, '0.0.0.0' ) )
tfod.listen( 512 )

reads << tfod
roles[ tfod ] = :server

loop do
  puts "select #{ reads.size }"
  rs, _ = IO.select( reads )

  rs.each do | sock |
    role = roles[ sock ]

    case role
    when :server
      client, addrinfo = sock.accept_nonblock
      puts "<<< #{ addrinfo.inspect }"
      reads << client
      roles[ client ] = :client
    when :client
      begin
        data = sock.read_nonblock( 65535 )
      rescue Exception => e
        puts "<<< #{ e.class }"
        sock.close
        reads.delete( sock )
        roles.delete( sock )
        next
      end

      puts "<<< #{ data.inspect }"
      data2 = 'ok'
      written = sock.write_nonblock( data2 )
      puts ">>> #{ data2 } #{ written }"
    end
  end
end
