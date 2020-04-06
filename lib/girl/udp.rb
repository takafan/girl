require 'girl/version'
require 'socket'

##
# Girl::Udp - 转发udp。近端。
#
# usage
# ======
#
# Girl::Udpd.new( 3030 ).looping # 远端
#
# Girl::Udp.new( 'your.server.ip', 3030, 1313 ).looping # 近端
#
# iptables -t nat -A PREROUTING -p udp -d game.server.ip -j REDIRECT --to-ports 1313
#
# p2p flow
# =========
#
# 源地址src发往第二个目的地dst2，iptables会映射一个新的本地端口sport2，用来代理dst2的返程。
# 可在nf_conntrack里找到src1和src2，看到映射前的源地址端口是一样的。
# 若在sport2没有收到返程30秒过期后，src发往第三个目的地dst3，iptables会把dst3的返程依旧映射在sport2上。因此不能根据映射端口建tun-tund对。
#
# tund1接到dst2，看作p2p进来，记tund1为src-dst2发送代理。
# 取接收者tund1.dst2.receiver，由接收者接数据。
# 若接收者为空，据dst2-src找接收者，找到tund2，tund2-tun2传数据，同时tund1发tund2.wmems去dst2。没找到，记tund1.dst2.rbuff。
#
# src经tun2-tund2发往dst2，记tund2为dst2-src接收者。
# 取发送代理tund2.alias_sender，由发送代理发数据。
# 若发送代理为空，据src-dst2找发送代理，找到tund1，tund1发数据给dst2，同时tund2转tund1.dst2.rbuffs给tun2。没找到，tund2-dst2，记tund2.wmem。
#
# 请求匹配服务器：
#
# redir recv -> src1, dst1, data -> tun1-tund1 data -> set receiver dst1-src: tund1 -> tund1-dst1 data
#
# 匹配服务器返回：
#
# tund1 recv -> dst1, data -> tund1-tun1 data -> redir-src1 data
#
# p1发往p2：
#
# redir recv -> src2, dst2, data -> tun2-tund2 data -> set receiver dst2-src: tund2 -> alias sender not found -> tund2-dst2 data -> save wmem
#
# p2后进来：
#
# tund1 recv -> dst2, data -> set alias sender src-dst2: tund1 -> found receiver tund2 -> tund2-tun2 redir-src2 data -> tund1-dst2 tund2.wmems
#
# p3进来：
#
# tund1 recv -> dst3, data -> set alias sender src-dst3: tund1 -> receiver not found -> save data to tund1.dst3.rbuffs
#
# p1后发往p3：
#
# redir recv -> src3, dst3, data -> tun3-tund3 data -> set receiver dst3-src: tund3 -> found alias sender tund1 -> tund1-dst3 data -> tund3-tun3 redir-src tund1.dst3.rbuffs
#
module Girl
  class Udp

    def initialize( udpd_host, udpd_port = 3030, redir_port = 1313 )
      ctlr, ctlw = IO.pipe

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      puts "redir bound on #{ redir_port } #{ Time.new }"

      @mutex = Mutex.new
      @udpd_host = udpd_host
      @udpd_addr = Socket.sockaddr_in( udpd_port, udpd_host )
      @ctlw = ctlw
      @redir = redir
      @reads = [ ctlr, redir ]
      @writes = []
      @closings = []
      @roles = {
        ctlr => :ctlr,   # :ctlr / :redir / :tun
        redir => :redir
      }
      @redir_wbuffs = [] # [ src_addr data ] ...
      @tuns = {}         # [ orig_src_addr dst_addr ]=> tun
      @mappings = {}     # src_addr => [ orig_src_addr dst_addr ]
      @tun_infos = {}    # tun => {}
                         #   orig_src_addr: sockaddr
                         #   dst_addr: sockaddr
                         #   src_addr: sockaddr
                         #   tund_addr: sockaddr
                         #   ctlmsgs: []
                         #   wbuffs: []
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
            when :tun
              read_tun( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :redir
              write_redir( sock )
            when :tun
              write_tun( sock )
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
      od_addr = ctlr.read( 32 )
      tun = @tuns[ od_addr ]

      if tun
        add_closing( tun )
      end
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      src_addr = addrinfo.to_sockaddr
      # puts "debug redir recv #{ data.inspect } from #{ addrinfo.inspect }"

      if @mappings.include?( src_addr )
        orig_src_addr, dst_addr = @mappings[ src_addr ]
      else
        # 2 udp 5 src 7 sport 9 [UNREPLIED] 11 dst 13 dport
        # 2 udp 5 src 7 sport 10 dst 12 dport
        is_add_mapping = false
        bin = IO.binread( '/proc/net/nf_conntrack' )
        rows = bin.split( "\n" ).map { | line | line.split( ' ' ) }
        row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 10 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 12 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port }

        if row
          is_add_mapping = true
        else
          row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 9 ] == '[UNREPLIED]' && _row[ 11 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 13 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port }

          unless row
            puts "miss conntrack #{ addrinfo.inspect } #{ Time.new }"
            IO.binwrite( '/tmp/nf_conntrack', bin )
            return
          end
        end

        orig_src_ip = row[ 5 ].split( '=' )[ 1 ]
        orig_src_port = row[ 7 ].split( '=' )[ 1 ].to_i
        dst_ip = row[ 6 ].split( '=' )[ 1 ]
        dst_port = row[ 8 ].split( '=' )[ 1 ].to_i
        orig_src_addr = Socket.sockaddr_in( orig_src_port, orig_src_ip )
        dst_addr = Socket.sockaddr_in( dst_port, dst_ip )

        if Addrinfo.new( dst_addr ).ipv4_private?
          puts "redir send to #{ Addrinfo.new( dst_addr ).inspect } from #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( orig_src_addr ).inspect } #{ Time.new }"
          @redir_wbuffs << [ dst_addr, data ]
          add_write( @redir )
          return
        end

        if is_add_mapping
          @mappings[ src_addr ] = [ orig_src_addr, dst_addr ]
        end
      end

      tun = @tuns[ [ orig_src_addr, dst_addr ].join ]

      unless tun
        tun = new_a_tun( orig_src_addr, dst_addr, src_addr )

        # puts "debug tun send to udpd #{ Addrinfo.new( orig_src_addr ).inspect } #{ Addrinfo.new( dst_addr ).inspect }"
        ctlmsg = [ orig_src_addr, dst_addr ].join
        add_ctlmsg( tun, ctlmsg )
      end

      add_write( tun, data )
    end

    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      from_addr = addrinfo.to_sockaddr
      tun_info = @tun_infos[ tun ]
      tun_info[ :last_traff_at ] = Time.new

      if from_addr == @udpd_addr
        tund_port = data[ 0, 2 ].unpack( 'n' ).first
        tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )
        tun_info[ :tund_addr ] = tund_addr
        add_write( tun )
      elsif from_addr == tun_info[ :tund_addr ]
        @redir_wbuffs << [ tun_info[ :src_addr ], data ]
        add_write( @redir )
      end
    end

    def write_redir( redir )
      if @redir_wbuffs.empty?
        @writes.delete( redir )
        return
      end

      src_addr, data = @redir_wbuffs.shift
      redir.sendmsg( data, 0, src_addr )
    end

    def write_tun( tun )
      if @closings.include?( tun )
        close_tun( tun )
        return
      end

      tun_info = @tun_infos[ tun ]
      ctlmsg = tun_info[ :ctlmsgs ].shift

      if ctlmsg
        tun.sendmsg( ctlmsg, 0, @udpd_addr )
        return
      end

      if tun_info[ :tund_addr ].nil? || tun_info[ :wbuffs ].empty?
        @writes.delete( tun )
        return
      end

      data = tun_info[ :wbuffs ].shift
      tun.sendmsg( data, 0, tun_info[ :tund_addr ] )
    end

    def add_ctlmsg( tun, ctlmsg )
      tun_info = @tun_infos[ tun ]
      tun_info[ :ctlmsgs ] << ctlmsg
      add_write( tun )
    end

    def add_write( sock, data = nil )
      if data
        tun_info = @tun_infos[ sock ]
        tun_info[ :wbuffs ] << data
      end

      unless @writes.include?( sock )
        @writes << sock
      end
    end

    def add_closing( tun )
      unless @closings.include?( tun )
        @closings << tun
      end

      add_write( tun )
    end

    def close_tun( tun )
      tun.close
      @reads.delete( tun )
      @writes.delete( tun )
      @closings.delete( tun )
      @roles.delete( tun )
      tun_info = @tun_infos.delete( tun )
      @tuns.delete( [ tun_info[ :orig_src_addr ], tun_info[ :dst_addr ] ].join )

      if @mappings.include?( tun_info[ :src_addr ] )
        orig_src_addr, dst_addr = @mappings[ tun_info[ :src_addr ] ]

        if orig_src_addr == tun_info[ :orig_src_addr ] && dst_addr == tun_info[ :dst_addr ]
          @mappings.delete( tun_info[ :src_addr ] )
        end
      end
    end

    def new_a_tun( orig_src_addr, dst_addr, src_addr )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      @tun_infos[ tun ] = {
        orig_src_addr: orig_src_addr,
        dst_addr: dst_addr,
        src_addr: src_addr,
        tund_addr: nil,
        ctlmsgs: [],
        wbuffs: [],
        last_traff_at: Time.new
      }

      @tuns[ [ orig_src_addr, dst_addr ].join ] = tun
      @roles[ tun ] = :tun
      @reads << tun

      tun
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 30

          @mutex.synchronize do
            now = Time.new

            @tun_infos.values.each do | tun_info |
              # net.netfilter.nf_conntrack_udp_timeout_stream
              if now - tun_info[ :last_traff_at ] > 180
                @ctlw.write( [ tun_info[ :orig_src_addr ], tun_info[ :dst_addr ] ].join )
              end
            end
          end
        end
      end
    end

  end
end
