require 'girl/version'
require 'socket'

##
# Girl::Udpd - udp透明转发，远端。
#
module Girl
  class Udpd

    def initialize( port = 3030 )
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}       # :dotr / :udpd / :tund
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
      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_udpd( port )
    end

    def looping
      loop_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          ws.each do | sock |
            case @roles[ sock ]
            when :udpd then
              write_udpd( sock )
            when :tund then
              write_tund( sock )
            end
          end

          rs.each do | sock |
            case @roles[ sock ]
            when :dotr then
              read_dotr( sock )
            when :udpd then
              read_udpd( sock )
            when :tund then
              read_tund( sock )
            end
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def loop_expire
      Thread.new do
        loop do
          sleep 30

          @mutex.synchronize do
            trigger = false
            now = Time.new

            @tund_infos.each do | tund, tund_info |
              # net.netfilter.nf_conntrack_udp_timeout_stream
              if now - tund_info[ :last_traff_at ] > 180 then
                set_is_closing( tund )
                trigger = true
              end
            end

            if trigger then
              next_tick
            end
          end
        end
      end
    end

    def new_a_udpd( port )
      udpd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udpd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "udpd bound on #{ port } #{ Time.new }"
      @udpd = udpd
      add_read( udpd, :udpd )
    end

    def pair_tund( tun_addr, tun_ip_addr, orig_src_addr, dst_addr )
      from_addr = [ tun_ip_addr, orig_src_addr ].join
      td_addr = [ tun_addr, dst_addr ].join
      tund = @tunds[ from_addr ]

      if tund then
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
          last_traff_at: Time.new,
          is_closing: false
        }

        @tunds[ from_addr ] = tund
        add_read( tund, :tund )
      end

      tund
    end

    def add_tund_wbuff( tund, to_addr, data )
      tund_info = @tund_infos[ tund ]
      tund_info[ :wbuffs ] << [ to_addr, data ]

      add_write( tund )
    end

    def add_read( sock, role )
      unless @reads.include?( sock ) then
        @reads << sock
      end

      @roles[ sock ] = role
    end

    def add_write( sock )
      unless @writes.include?( sock ) then
        @writes << sock
      end
    end

    def set_is_closing( tund )
      if tund && !tund.closed? then
        # puts "debug1 set tund is closing"

        tund_info = @tund_infos[ tund ]
        tund_info[ :is_closing ] = true

        @reads.delete( tund )
        add_write( tund )
      end
    end

    def send_data( sock, data, to_addr )
      begin
        sock.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        if @roles[ sock ] == :tund then
          puts "#{ Time.new } #{ e.class }, close tund"
          close_tund( sock )
          return false
        end
      end

      true
    end

    def close_tund( tund )
      tund.close
      @reads.delete( tund )
      @writes.delete( tund )
      @roles.delete( tund )
      tund_info = @tund_infos.delete( tund )
      @tunds.delete( [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join )
    end

    def next_tick
      @dotw.write( '.' )
    end

    def write_udpd( udpd )
      while @udpd_wbuffs.any? do
        to_addr, data = @udpd_wbuffs.first

        return unless send_data( udpd, data, to_addr )

        @udpd_wbuffs.shift
      end

      @writes.delete( udpd )
    end

    def write_tund( tund )
      tund_info = @tund_infos[ tund ]

      if tund_info[ :is_closing ] then
        close_tund( tund )
        return
      end

      while tund_info[ :wbuffs ].any? do
        to_addr, data = tund_info[ :wbuffs ].first

        return unless send_data( tund, data, to_addr )

        tund_info[ :wbuffs ].shift
      end

      @writes.delete( tund )
    end

    def read_dotr( dotr )
      dotr.read( 1 )
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

      if to_addr then
        # 来自tun，发给dst。
        td_addr = [ from_addr, to_addr ].join
        is_tunneled = tund_info[ :is_tunneleds ][ td_addr ]

        unless is_tunneled then
          # puts "debug first traffic from tun #{ addrinfo.inspect } to #{ Addrinfo.new( to_addr ).inspect }"
          # 发暂存
          if tund_info[ :unpaired_dst_rbuffs ].include?( to_addr ) then
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

      if to_addr then
        # 来自dst，发给tun。
        # puts "debug #{ data.inspect } from #{ addrinfo.inspect } to #{ Addrinfo.new( to_addr ).inspect }"

        td_addr = [ to_addr, from_addr ].join
        is_tunneled = tund_info[ :is_tunneleds ][ td_addr ]

        if is_tunneled then
          add_tund_wbuff( tund, to_addr, data )
          return
        end

        # puts "debug #{ Addrinfo.new( to_addr ).inspect } #{ addrinfo.inspect } not tunneled"
      end

      # 来自未知的地方，或者对应的tun还没来流量，记暂存
      unless tund_info[ :unpaired_dst_rbuffs ][ from_addr ] then
        tund_info[ :unpaired_dst_rbuffs ][ from_addr ] = []
      end

      # 暂存5条（连发打洞数据，不需要存多）。
      if tund_info[ :unpaired_dst_rbuffs ][ from_addr ].size < 5 then
        # puts "debug save other dst rbuff #{ addrinfo.inspect } #{ data.inspect }"
        tund_info[ :unpaired_dst_rbuffs ][ from_addr ] << data
      end
    end

  end
end
