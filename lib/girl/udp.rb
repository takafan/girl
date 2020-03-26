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
      ctlr, ctlw = IO.pipe

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

      @mutex = Mutex.new
      @udpd_addr = Socket.sockaddr_in( udpd_port, udpd_host )
      @ctlw = ctlw
      @redir = redir
      @udp = udp
      @reads = [ ctlr, redir, udp ]
      @writes = []
      @closings = []
      @roles = {
        ctlr => :ctlr, # :ctlr / :redir / :udp / :src
        redir => :redir,
        udp => :udp
      }
      @srcs = {}      # dest_addr => src
      @src_infos = {} # src => {}
                      #   dest_addr: dest_addr
                      #   src_addr: src_addr
                      #   last_traff_at: now
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
            when :src
              read_src( sock )
            end
          end

          ws.each do | sock |
            write_src( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      dest_addr = ctlr.read( 16 )
      src = @srcs[ dest_addr ]

      if src
        # puts "debug expire src #{ dest_addr.inspect } #{ Time.new }"
        add_closing( src )
      end
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      # puts "debug #{ data.inspect } #{ Time.new }"
      # puts "debug #{ controls.inspect } #{ Time.new }"

      from_addr = addrinfo.to_sockaddr
      ancdata = controls.find { | _ancdata | _ancdata.cmsg_is?( Socket::SOL_IP, 20 ) }
      to_addr = ancdata.data

      @udp.sendmsg( "#{ from_addr }#{ to_addr }#{ data }", 0, @udpd_addr )
    end

    def read_udp( udp )
      data, addrinfo, rflags, *controls = udp.recvmsg
      return if data.size < 17

      dest_addr = data[ 0, 16 ]
      src_addr = data[ 16, 16 ]
      data = data[ 32..-1 ]

      src = @srcs[ dest_addr ]

      unless src
        src = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        src.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        src.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
        # puts "debug a new src bound on #{ src.local_address.ip_unpack.last } #{ Time.new }"

        @srcs[ dest_addr ] = src
        @src_infos[ src ] = {
          dest_addr: dest_addr,
          src_addr: src_addr,
          wbuffs: [],
          last_traff_at: Time.new
        }

        @roles[ src ] = :src
        @reads << src
      end

      src_info = @src_infos[ src ]
      src_info[ :wbuffs ] << data
      add_write( src )
    end

    def read_src( src )
      data, addrinfo, rflags, *controls = src.recvmsg

      src_info = @src_infos[ src ]
      return unless src_info

      src_info[ :last_traff_at ] = Time.new
      from_addr = addrinfo.to_sockaddr
      @udp.sendmsg( "#{ from_addr }#{ src_info[ :dest_addr ] }#{ data }", 0, @udpd_addr )
    end

    def write_src( src )
      if @closings.include?( src )
        close_src( src )
        return
      end

      src_info = @src_infos[ src ]
      data = src_info[ :wbuffs ].shift

      unless data
        @writes.delete( src )
        return
      end

      begin
        src.sendmsg( data, 0, src_info[ :src_addr ] )
      rescue Errno::EACCES, Errno::EINTR => e
        puts "src sendmsg #{ e.class } #{ Time.new }"
        add_closing( src )
        return
      end

      src_info[ :last_traff_at ] = Time.new
    end

    def add_write( src )
      unless @writes.include?( src )
        @writes << src
      end
    end

    def add_closing( src )
      unless @closings.include?( src )
        @closings << src
      end

      add_write( src )
    end

    def close_src( src )
      src.close
      @reads.delete( src )
      @writes.delete( src )
      @closings.delete( src )
      @roles.delete( src )
      src_info = @src_infos.delete( src )
      @srcs.delete( src_info[ :dest_addr ] )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @src_infos.values.each do | src_info |
              if now - src_info[ :last_traff_at ] > 1800
                @ctlw.write( src_info[ :dest_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
