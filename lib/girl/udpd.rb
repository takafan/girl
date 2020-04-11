require 'girl/version'
require 'socket'

##
# Girl::Udpd - 转发udp。远端。
#
module Girl
  class Udpd

    def initialize( port = 3030 )
      ctlr, ctlw = IO.pipe

      udpd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udpd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "udpd bound on #{ port } #{ Time.new }"

      @mutex = Mutex.new
      @ctlw = ctlw
      @udpd = udpd
      @reads = [ ctlr, udpd ]
      @writes = []
      @closings = []
      @roles = {
        ctlr => :ctlr,  # :ctlr / :udpd / :tund
        udpd => :udpd
      }
      @udpd_wbuffs = [] # [ tun_addr ctlmsg ] ...
      @tunds = {}       # [ tun_ip_addr orig_src_addr ] => tund
      @tund_infos = {}  # tund => {}
                        #   port: port
                        #   tun_ip_addr: sockaddr
                        #   orig_src_addr: sockaddr
                        #   wbuffs: [] # [ to_addr, data ] ...
                        #   dst_addrs: { tun_addr => dst_addr }
                        #   tun_addrs: { dst_addr => tun_addr }
                        #   is_tunneleds: { [ tun_addr dst_addr ] => false }
                        #   unpaired_dst_rbuffs: { dst_addr => [] }
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
            when :udpd
              read_udpd( sock )
            when :tund
              read_tund( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :udpd
              write_udpd( sock )
            when :tund
              write_tund( sock )
            end
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      to_addr = ctlr.read( 32 )
      tund = @tunds[ to_addr ]

      if tund
        add_closing( tund )
      end
    end

    def read_udpd( udpd )
      data, addrinfo, rflags, *controls = udpd.recvmsg
      # puts "debug udpd recv #{ data.inspect } from #{ addrinfo.inspect }"
      orig_src_addr = data[ 0, 16 ]
      dst_addr = data[ 16, 16 ]
      tun_addr = addrinfo.to_sockaddr
      tun_ip_addr = Addrinfo.ip( addrinfo.ip_address ).to_sockaddr

      return unless Addrinfo.new( orig_src_addr ).ipv4?

      dst_addrinfo = Addrinfo.new( dst_addr )
      return unless dst_addrinfo.ipv4?
      return if dst_addrinfo.ipv4_private?

      tund = pair_tund( tun_addr, tun_ip_addr, orig_src_addr, dst_addr )
      tund_info = @tund_infos[ tund ]
      tund_port = tund_info[ :port ]

      # puts "debug udpd send to tun #{ tund_port } #{ addrinfo.inspect }"
      ctlmsg = [ tund_port ].pack( 'n' )
      @udpd_wbuffs << [ tun_addr, ctlmsg ]
      add_write( udpd )
    end

    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      from_addr = addrinfo.to_sockaddr
      tund_info = @tund_infos[ tund ]
      tund_info[ :last_traff_at ] = Time.new
      to_addr = tund_info[ :dst_addrs ][ from_addr ]

      if to_addr
        # 来自tun，发给dst。
        td_addr = [ from_addr, to_addr ].join
        is_tunneled = tund_info[ :is_tunneleds ][ td_addr ]

        unless is_tunneled
          # puts "debug first traffic from tun #{ addrinfo.inspect } to #{ Addrinfo.new( to_addr ).inspect }"
          # 发暂存
          if tund_info[ :unpaired_dst_rbuffs ].include?( to_addr )
            rbuffs = tund_info[ :unpaired_dst_rbuffs ].delete( to_addr )
            # puts "debug move tund.dst.rbuffs to tund.wbuffs #{ rbuffs.inspect }"
            tund_info[ :wbuffs ] += rbuffs.map{ | rbuff | [ from_addr, rbuff ] }
          end

          tund_info[ :is_tunneleds ][ td_addr ] = true
        end

        # 如果对面没来过流量，且在nat里，nat规则是只对去过的目的地做接收，那么，先过去的流量会撞死。
        # 没关系，撞死的流量通常是打洞数据，在应用计算之内，打洞数据通常是连发的。
        # puts "debug #{ data.inspect } from #{ addrinfo.inspect } to #{ Addrinfo.new( to_addr ).inspect }"
        add_tund_wbuff( tund, to_addr, data )
        return
      end

      to_addr = tund_info[ :tun_addrs ][ from_addr ]

      if to_addr
        # 来自dst，发给tun。
        # puts "debug #{ data.inspect } from #{ addrinfo.inspect } to #{ Addrinfo.new( to_addr ).inspect }"

        td_addr = [ to_addr, from_addr ].join
        is_tunneled = tund_info[ :is_tunneleds ][ td_addr ]

        if is_tunneled
          add_tund_wbuff( tund, to_addr, data )
          return
        end

        # puts "debug #{ Addrinfo.new( to_addr ).inspect } #{ addrinfo.inspect } not tunneled"
      end

      # 来自未知的地方，或者对应的tun还没来流量，记暂存
      unless tund_info[ :unpaired_dst_rbuffs ][ from_addr ]
        tund_info[ :unpaired_dst_rbuffs ][ from_addr ] = []
      end

      # 暂存5条（连发打洞数据，不需要存多）。
      if tund_info[ :unpaired_dst_rbuffs ][ from_addr ].size < 5
        # puts "debug save other dst rbuff #{ addrinfo.inspect } #{ data.inspect }"
        tund_info[ :unpaired_dst_rbuffs ][ from_addr ] << data
      end
    end

    def write_udpd( udpd )
      if @udpd_wbuffs.empty?
        @writes.delete( udpd )
        return
      end

      tun_addr, ctlmsg = @udpd_wbuffs.shift
      udpd.sendmsg( ctlmsg, 0, tun_addr )
    end

    def write_tund( tund )
      if @closings.include?( tund )
        close_tund( tund )
        return
      end

      tund_info = @tund_infos[ tund ]

      if tund_info[ :wbuffs ].empty?
        @writes.delete( tund )
        return
      end

      to_addr, data = tund_info[ :wbuffs ].shift
      tund.sendmsg( data, 0, to_addr )
    end

    def add_tund_wbuff( tund, to_addr, data )
      tund_info = @tund_infos[ tund ]
      tund_info[ :wbuffs ] << [ to_addr, data ]

      add_write( tund )
    end

    def add_write( sock )
      unless @writes.include?( sock )
        @writes << sock
      end
    end

    def add_closing( tund )
      unless @closings.include?( tund )
        @closings << tund
      end

      add_write( tund )
    end

    def close_tund( tund )
      tund.close
      @reads.delete( tund )
      @writes.delete( tund )
      @closings.delete( tund )
      @roles.delete( tund )
      tund_info = @tund_infos.delete( tund )
      @tunds.delete( [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join )
    end

    def pair_tund( tun_addr, tun_ip_addr, orig_src_addr, dst_addr )
      from_addr = [ tun_ip_addr, orig_src_addr ].join
      td_addr = [ tun_addr, dst_addr ].join
      tund = @tunds[ from_addr ]

      if tund
        tund_info = @tund_infos[ tund ]
        tund_info[ :dst_addrs ][ tun_addr ] = dst_addr
        tund_info[ :tun_addrs ][ dst_addr ] = tun_addr
        tund_info[ :is_tunneleds ][ td_addr ] = false
      else
        tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1 )
        tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
        tund_port = tund.local_address.ip_unpack.last

        @tund_infos[ tund ] = {
          port: tund_port,
          tun_ip_addr: tun_ip_addr,
          orig_src_addr: orig_src_addr,
          wbuffs: [],
          dst_addrs: { tun_addr => dst_addr },
          tun_addrs: { dst_addr => tun_addr },
          is_tunneleds: { td_addr => false },
          unpaired_dst_rbuffs: {},
          last_traff_at: Time.new
        }

        @roles[ tund ] = :tund
        @reads << tund
        @tunds[ from_addr ] = tund
      end

      tund
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 30

          @mutex.synchronize do
            now = Time.new

            @tund_infos.values.each do | tund_info |
              # net.netfilter.nf_conntrack_udp_timeout_stream
              if now - tund_info[ :last_traff_at ] > 180
                @ctlw.write( [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join )
              end
            end
          end
        end
      end
    end

  end
end
