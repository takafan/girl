require 'girl/version'
require 'socket'

##
# Girl::Udp - 转发udp。近端。
#
# usage
# =====
#
# Girl::Udpd.new( 3030 ).looping # 远端
#
# Girl::Udp.new( 'your.server.ip', 3030, 1313 ).looping # 近端
#
# apt-get install xtables-addons-dkms
# echo 'nf_tproxy_ipv4' > /etc/modules-load.d/nf_tproxy_ipv4.conf
#
# iptables -t mangle -I PREROUTING -p udp -d game.server.ip -j TPROXY --tproxy-mark 0x1/0x1 --on-port 1313
#
# ip rule add fwmark 1 lookup 100
# ip route add local 0.0.0.0/0 dev lo table 100
#
module Girl
  class Udp

    def initialize( udpd_host, udpd_port = 3030, redir_port = 1313 )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_IP, 19, 1 )
      redir.setsockopt( Socket::SOL_IP, 20, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      puts "redir bound on #{ redir_port } #{ Time.new }"

      udp = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udp.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udp.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      puts "udp bound on #{ udp.local_address.ip_unpack.last } #{ Time.new }"

      @udpd_addr = Socket.sockaddr_in( udpd_port, udpd_host )
      @redir = redir
      @udp = udp
      @roles = {
        redir => :redir,
        udp => :udp
      }
    end

    def looping
      loop do
        rs, _ = IO.select( [ @redir, @udp ] )

        rs.each do | sock |
          case @roles[ sock ]
          when :redir
            read_redir( sock )
          when :udp
            read_udp( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      # puts "debug #{ data.inspect } #{ Time.new }"
      # puts "debug #{ controls.inspect } #{ Time.new }"

      src_addr = addrinfo.to_sockaddr
      ancdata = controls.find { | _ancdata | _ancdata.cmsg_is?( Socket::SOL_IP, 20 ) }
      dest_addr = ancdata.data

      @udp.sendmsg( "#{ src_addr }#{ dest_addr }#{ data }", 0, @udpd_addr )
    end

    def read_udp( udp )
      data, addrinfo, rflags, *controls = udp.recvmsg
      return if data.size < 17

      src_addr = data[ 0, 16 ]
      data = data[ 16..-1 ]

      @redir.sendmsg( data, 0, src_addr )
    end

  end
end
