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
# control message
# ================
#
# C: 1 (tun > udpd: req a tund) -> src_addr -> dest_addr
# C: 2 (udpd > tun: tund port) -> n: tund_port -> tun_addr
# C: 3 (udpd > tun: req a chain tun) -> new_dest_addr -> orig_tun_addr
# C: 4 (tun > udpd: req a chain tund) -> src_addr -> dest_addr -> orig_tun_addr
# C: 5 (tun > tund: hello)
#
# flow
# =====
#
# src-dst1: src-redir -> tun1-tund1 -> tund1-dst1
# src-dst2: src-redir -> tun2-tund2 -> tund1-dst2
# dst3-src: dst3-tund1 -> tun3-tund3 -> tund3-tun3 -> tun3-src
#
# detailed flow
# ==============
#
# src-dst2: src -> redir -> new tun2 -> tun2.orig_tun = tun1 = orig_tuns[src_addr]
#   -> ctlmsg.4 src_addr dest_addr tun1.tund_port -> new tund2 -> tund2.orig_tund=tund1 -> tund1-dst2
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
      @orig_tuns = {}    # src_addr => tun
      @tuns = {}         # [ src_addr dest_addr ] => tun
      @tun_infos = {}    # tun => {}
                         #   src_addr: sockaddr
                         #   is_src_accepted: true # tun可能先根据ctlmsg.3创建，该值设为false。redir收到src的流量后，更新该值为true。
                         #   dest_addr: sockaddr
                         #   tun_addr: sockaddr
                         #   tund_addr: sockaddr
                         #   orig_tun: tun1
                         #   ctlmsgs: []
                         #   wbuffs: []
                         #   dest_rbuffs: []
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
      sd_addr = ctlr.read( 32 )
      tun = @tuns[ sd_addr ]

      if tun
        add_closing( tun )
      end
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      src_addr = addrinfo.to_sockaddr

      # puts "debug redir recv #{ data.inspect } from #{ addrinfo.inspect }"
      # 2 udp 9 [UNREPLIED] 11 dst 13 dport
      # 2 udp 10 dst 12 dport 13 [ASSURED]
      bin = IO.binread( '/proc/net/nf_conntrack' )
      rows = bin.split( "\n" ).map { | line | line.split( ' ' ) }
      row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 9 ] == '[UNREPLIED]' && _row[ 11 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 13 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port }

      unless row
        row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 10 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 12 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port && _row[ 13 ] == '[ASSURED]' }

        unless row
          puts "miss conntrack #{ addrinfo.inspect } #{ Time.new }"
          IO.binwrite( '/tmp/nf_conntrack', bin )
          return
        end
      end

      dest_ip = row[ 6 ].split( '=' )[ 1 ]
      dest_port = row[ 8 ].split( '=' )[ 1 ].to_i
      dest_addr = Socket.sockaddr_in( dest_port, dest_ip )
      tun = @tuns[ [ src_addr, dest_addr ].join ]

      if tun
        tun_info = @tun_infos[ tun ]

        unless tun_info[ :is_src_accepted ]
          # p2p successed
          tun_info[ :is_src_accepted ] = true

          if tun_info[ :dest_rbuffs ].any?
            puts "relay p2p buffer from dest #{ Addrinfo.new( tun_info[ :dest_addr ] ).inspect } to #{ addrinfo.inspect }"
            @redir_wbuffs += tun_info[ :dest_rbuffs ].map{ | buff | [ src_addr, buff ] }
            tun_info[ :dest_rbuffs ].clear
            add_redir_write( redir )
          end
        end
      else
        tun = new_a_tun( src_addr, dest_addr )
        tun_info = @tun_infos[ tun ]

        # puts "debug send C: 1 (tun > udpd: req a tund) -> src_addr dest_addr #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( dest_addr ).inspect }"
        ctlmsg = [ [ 1 ].pack( 'C' ), src_addr, dest_addr ].join
        add_ctlmsg( tun, ctlmsg )
      end

      tun_info = @tun_infos[ tun ]
      add_write( tun, data )
    end

    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      from_addr = addrinfo.to_sockaddr
      tun_info = @tun_infos[ tun ]
      tun_info[ :last_traff_at ] = Time.new

      if from_addr == @udpd_addr
        ctl_num = data[ 0 ].unpack( 'C' ).first

        case ctl_num
        when 2 # C: 2 (udpd > tun: tund port) -> n: tund_port -> tun_addr
          return if tun_info[ :tund_addr ]

          tund_port = data[ 1, 2 ].unpack( 'n' ).first
          tun_addr = data[ 3, 16 ]
          tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )
          tun_info[ :tun_addr ] = tun_addr
          tun_info[ :tund_addr ] = tund_addr

          # tun flush wbuffs to tund, if empty, just send a (5: hello) to cross nat, tund should ignore hello
          if tun_info[ :wbuffs ].empty?
            tun_info[ :wbuffs ] << [ 5 ].pack( 'C' )
          end

          add_write( tun )
        when 3 # C: 3 (udpd > tun: req a chain tun) -> new_dest_addr tun_addr
          new_dest_addr = data[ 1, 16 ]
          src_addr = tun_info[ :src_addr ]
          chain_tun = @tuns[ [ src_addr, new_dest_addr ].join ]

          unless chain_tun
            chain_tun = new_a_tun( src_addr, new_dest_addr, is_src_accepted = false )
          end

          orig_tun_addr = tun_info[ :tun_addr ]

          unless orig_tun_addr
            orig_tun_addr = tun_info[ :tun_addr ] = data[ 17, 16 ]
          end

          # puts "debug send C: 4 (tun > udpd: req a chain tund) -> src_addr dest_addr orig_tun_addr #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( new_dest_addr ).inspect } #{ Addrinfo.new( orig_tun_addr ).inspect }"
          ctlmsg = [ [ 4 ].pack( 'C' ), src_addr, new_dest_addr, orig_tun_addr ].join
          add_ctlmsg( chain_tun, ctlmsg )
        end
      elsif from_addr == tun_info[ :tund_addr ]
        if tun_info[ :is_src_accepted ]
          @redir_wbuffs << [ tun_info[ :src_addr ], data ]
          add_redir_write( @redir )
          return
        end

        # puts "debug save to :dest_rbuffs #{ data.inspect }"
        tun_info[ :dest_rbuffs ] << data
      elsif from_addr == tun_info[ :src_addr ]
        add_write( tun, data )
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

      unless @writes.include?( tun )
        @writes << tun
      end
    end

    def add_write( tun, data = nil )
      tun_info = @tun_infos[ tun ]

      if data
        tun_info[ :wbuffs ] << data
      end

      unless @writes.include?( tun )
        @writes << tun
      end
    end

    def add_redir_write( redir )
      unless @writes.include?( redir )
        @writes << redir
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
      @tuns.delete( [ tun_info[ :src_addr ], tun_info[ :dest_addr ] ].join )

      unless tun_info[ :orig_tun ]
        @orig_tuns.delete( tun_info[ :src_addr ] )
      end
    end

    def new_a_tun( src_addr, dest_addr, is_src_accepted = true )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      orig_tun = @orig_tuns[ src_addr ]
      @tuns[ [ src_addr, dest_addr ].join ] = tun
      @tun_infos[ tun ] = {
        src_addr: src_addr,
        is_src_accepted: is_src_accepted,
        dest_addr: dest_addr,
        tun_addr: nil,
        tund_addr: nil,
        orig_tun: orig_tun,
        ctlmsgs: [],
        wbuffs: [],
        dest_rbuffs: [],
        last_traff_at: Time.new
      }

      @roles[ tun ] = :tun
      @reads << tun

      unless orig_tun
        @orig_tuns[ src_addr ] = tun
      end

      tun
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @tun_infos.values.each do | tun_info |
              if now - tun_info[ :last_traff_at ] > 1800
                @ctlw.write( [ tun_info[ :src_addr ], tun_info[ :dest_addr ] ].join )
              end
            end
          end
        end
      end
    end

  end
end
