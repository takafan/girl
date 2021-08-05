require 'json'
require 'socket'

close_client_after = ARGV[ 0 ] ? ARGV[ 0 ].to_i : 0
config_path = File.expand_path( '../test.conf.json', __FILE__ )
config = JSON.parse( IO.binread( config_path ), symbolize_names: true )
puts config.inspect

server_ip = config[ :server_ip ]
server_port = config[ :server_port ]
proxy_host = config[ :proxy_host ]
proxy_port = config[ :proxy_port ]

data = <<EOF
CONNECT #{ server_ip }:#{ server_port } HTTP/1.1
Host: #{ server_ip }:#{ server_port }
Proxy-Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36
EOF

reads = []
roles = {}

client = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
client.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
client.connect( Socket.sockaddr_in( proxy_port, proxy_host ) )
puts "write #{ data.inspect }"
client.write( data )
reads << client
roles[ client ] = :client

loop do
  puts 'select'
  rs, _ = IO.select( reads )

  rs.each do | sock |
    role = roles[ sock ]

    case role
    when :client
      begin
        data = sock.read_nonblock( 65535 )
      rescue Exception => e
        puts "read client #{ e.class }"
        sock.close
        reads.delete( sock )
        roles.delete( sock )
        next
      end

      puts "read client #{ data.inspect }"

      if data == "HTTP/1.1 200 OK\r\n\r\n" then
        data2 = "lala"
        puts "write #{ data2.inspect }"
        sock.write( data2 )

        if close_client_after > 0 then
          sleep close_client_after
          puts 'close client'
          reads.delete( client )
          roles.delete( client )
          client.close
        end
      end
    end
  end
end
