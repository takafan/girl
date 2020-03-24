require 'girl/hex'
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
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {} # sock => :ctlr / :redir / :udp
      @infos = {} # redir => {}

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_IP, 19, 1 )
      redir.setsockopt( Socket::SOL_IP, 20, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      puts "redir bound on #{ redir_port } #{ Time.new }"

      redir_info = {
        udpd_addr: Socket.sockaddr_in( udpd_port, udpd_host ),
        src_addrs: {}, # src_addr => udp
        udp_ids: {},   # udp_id => udp
        udps: {}       # udp => {
                       #   src_addr: src_addr,
                       #   last_recv_at: now
                       # }
      }

      @redir = redir
      @redir_info = redir_info
      @roles[ redir ] = :redir
      @infos[ redir ] = redir_info
      @reads << redir

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr
    end

    def looping
      loop_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          rs.each do | sock |
            case @roles[ sock ]
            when :ctlr
              read_ctlr( sock )
            when :redir
              read_redir( sock )
            when :udp
              read_udp( sock )
            end
          end

          ws.each do | sock |
            close_udp( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      udp_id = ctlr.read( 8 ).unpack( 'Q>' ).first
      udp = @redir_info[ :udp_ids ][ udp_id ]

      if udp
        # puts "debug expire #{ @roles[ udp ] } #{ udp_id } #{ Time.new }"

        unless @writes.include?( udp )
          @writes << udp
        end
      end
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg

      # puts "debug #{ data.inspect } #{ Time.new }"
      # puts "debug #{ controls.inspect } #{ Time.new }"

      now = Time.new
      info = @infos[ redir ]
      src_addr = addrinfo.to_sockaddr
      udp = info[ :src_addrs ][ src_addr ]

      unless udp
        udp = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        udp.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        udp.setsockopt( Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1 )
        udp.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

        # puts "debug a new udp bound on #{ udp.local_address.ip_unpack.last } #{ Time.new }"

        udp_id = @hex.gen_random_num
        info[ :src_addrs ][ src_addr ] = udp
        info[ :udp_ids ][ udp_id ] = udp
        info[ :udps ][ udp ] = {
          udp_id: udp_id,
          src_addr: src_addr,
          last_recv_at: now
        }

        @roles[ udp ] = :udp
        @reads << udp

        ancdata = controls.find { | _ancdata | _ancdata.cmsg_is?( Socket::SOL_IP, 20 ) }
        dest_addr = ancdata.data
        udp.sendmsg( dest_addr, 0, info[ :udpd_addr ] )
      end

      udp.sendmsg( data, 0, info[ :udpd_addr ] )
    end

    def read_udp( udp )
      data, addrinfo, rflags, *controls = udp.recvmsg

      udp_info = @redir_info[ :udps ][ udp ]
      return unless udp_info

      udp_info[ :last_recv_at ] = Time.new
      @redir.sendmsg( data, 0, udp_info[ :src_addr ] )
    end

    def close_udp( udp )
      udp.close
      @reads.delete( udp )
      @writes.delete( udp )
      @roles.delete( udp )
      udp_info = @redir_info[ :udps ].delete( udp )
      @redir_info[ :src_addrs ].delete( udp_info[ :src_addr ] )
      @redir_info[ :udp_ids ].delete( udp_info[ :udp_id ] )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @redir_info[ :udps ].values.each do | udp_info |
              if now - udp_info[ :last_recv_at ] > 3600
                @ctlw.write( [ udp_info[ :udp_id ] ].pack( 'Q>' ) )
              end
            end
          end
        end
      end
    end

  end
end
