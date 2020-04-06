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
        ctlr => :ctlr,        # :ctlr / :udpd / :tund
        udpd => :udpd
      }
      @udpd_wbuffs = []       # [ tun_addr ctlmsg ] ...
      @tunds = {}             # tun_addr => tund
      @orig_tunds = {}        # [ tun_ip_addr orig_src_addr ] => tund
      @alias_senders = {}     # [ tun_ip_addr orig_src_addr dst_addr ] => tund # alias senders to dst
      @receivers = {}         # [ dst_addr tun_ip_addr orig_src_addr ] => tund # receivers from dst
      @tund_infos = {}        # tund => {}
                              #   port: port
                              #   tun_addr: sockaddr
                              #   tun_ip_addr: sockaddr
                              #   orig_src_addr: sockaddr
                              #   dst_addr: sockaddr
                              #   wbuffs: [] # 写往tun的写前缓存
                              #   wmems: [] # 写往dst的写后缓存
                              #   other_dst_rbuffs: { new_dst_addr => [] }
                              #   receivers: { other_dst_addr => other_tund }
                              #   last_traff_at: now
      @od_addr_rbuffs = {}
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
      tun_addr = ctlr.read( 16 )
      tund = @tunds[ tun_addr ]

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
      return unless Addrinfo.new( dst_addr ).ipv4?

      tund = @tunds[ tun_addr ]

      unless tund
        tund = new_a_tund( tun_addr, tun_ip_addr, orig_src_addr, dst_addr )
      end

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

      case from_addr
      when tund_info[ :tun_addr ]
        # src经tun2-tund2发往dst2，记tund2为dst2-src接收者。
        dto_addr = [ tund_info[ :dst_addr ], tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join

        if @receivers[ dto_addr ]
          if @receivers[ dto_addr ] != tund
            puts "receiver not unique? #{ Addrinfo.new( tund_info[ :dst_addr ] ).inspect } #{ Addrinfo.new( tund_info[ :tun_ip_addr ] ).inspect } #{ Addrinfo.new( tund_info[ :orig_src_addr ] ).inspect }"
            return
          end
        else
          @receivers[ dto_addr ] = tund
        end

        # 取发送代理tund2.alias_sender，由发送代理发数据。
        sender = tund_info[ :alias_sender ]

        if sender
          # puts "debug alias sender send #{ data.inspect } to #{ Addrinfo.new( tund_info[ :dst_addr ] ).inspect }"
          send_to_dst( sender, data, tund_info[ :dst_addr ] )
        else
          # 若发送代理为空，据src-dst2找发送代理，找到tund1，tund1发数据给dst2，同时tund2转tund1.dst2.rbuffs给tun2。没找到，tund2-dst2，记tund2.wmem。
          tod_addr = [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], tund_info[ :dst_addr ] ].join
          sender = @alias_senders[ tod_addr ]

          if sender
            send_to_dst( sender, data, tund_info[ :dst_addr ] )
            tund_info[ :alias_sender ] = sender

            sender_info = @tund_infos[ sender ]
            rbuffs = sender_info[ :other_dst_rbuffs ].delete( tund_info[ :dst_addr ] )

            if rbuffs
              # puts "debug move tund1.dst2.rbuffs to tund2.wbuffs #{ rbuffs.inspect }"
              tund_info[ :wbuffs ] += rbuffs
              add_write( tund )
            end
          else
            to_addr = [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join
            orig_tund = @orig_tunds[ to_addr ]
            send_to_dst( orig_tund, data, tund_info[ :dst_addr ] )

            # 缓存写后，可能是p2p自己先出去，撞死的流量，之后对面进来匹配成对，由发送代理重发。超过5条看做非p2p。
            if tund_info[ :wmems ].size < 5
              # puts "debug save wmem #{ data.inspect } #{ Addrinfo.new( tund_info[ :dst_addr ] ).inspect }"
              tund_info[ :wmems ] << data
            end
          end
        end
      when tund_info[ :dst_addr ]
        # puts "debug tund-tun #{ data.inspect } from #{ Addrinfo.new( tund_info[ :dst_addr ] ).inspect }"
        add_write( tund, data )
      else
        # tund1接到dst2，看作p2p进来，记tund1为src-dst2发送代理。
        # puts "debug tund recv #{ data.inspect } from #{ addrinfo.inspect }"
        tod_addr = [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], from_addr ].join

        if @alias_senders[ tod_addr ]
          if @alias_senders[ tod_addr ] != tund
            puts "alias sender not unique? #{ Addrinfo.new( tund_info[ :tun_ip_addr ] ).inspect } #{ Addrinfo.new( tund_info[ :orig_src_addr ] ).inspect } #{ addrinfo.inspect }"
            return
          end
        else
          @alias_senders[ tod_addr ] = tund
        end

        # 取接收者tund1.dst2.receiver，由接收者接数据。
        receiver = tund_info[ :receivers ][ from_addr ]

        if receiver
          receiver_info = @tund_infos[ receiver ]
          add_write( receiver, data )
        else
          # 若接收者为空，据dst2-src找接收者，找到tund2，tund2-tun2传数据，同时tund1转tund2.wmems给dst2。没找到，记tund1.dst2.rbuff。
          dto_addr = [ from_addr, tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join
          receiver = @receivers[ dto_addr ]

          if receiver
            add_write( receiver, data )

            tund_info[ :receivers ][ from_addr ] = receiver
            receiver_info = @tund_infos[ receiver ]

            receiver_info[ :wmems ].each do | wmem |
              # puts "debug send wmem #{ wmem.inspect } to #{ addrinfo.inspect }"
              send_to_dst( tund, wmem, from_addr )
            end

            receiver_info[ :wmems ].clear
          else
            unless tund_info[ :other_dst_rbuffs ][ from_addr ]
              tund_info[ :other_dst_rbuffs ][ from_addr ] = []
            end

            # 暂存对面先到的p2p流量。超过5条看做意外数据忽略。
            if tund_info[ :other_dst_rbuffs ][ from_addr ].size < 5
              # puts "debug save other dst rbuff #{ addrinfo.inspect } #{ data.inspect }"
              tund_info[ :other_dst_rbuffs ][ from_addr ] << data
            end
          end
        end
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

      data = tund_info[ :wbuffs ].shift
      tund.sendmsg( data, 0, tund_info[ :tun_addr ] )
      tund_info[ :last_traff_at ] = Time.new
    end

    def send_to_dst( tund, data, dst_addr )
      tund.sendmsg( data, 0, dst_addr )
      tund_info = @tund_infos[ tund ]
      tund_info[ :last_traff_at ] = Time.new
    end

    def add_write( sock, data = nil )
      if data
        tund_info = @tund_infos[ sock ]
        tund_info[ :wbuffs ] << data
      end

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
      @tunds.delete( tund_info[ :tun_addr ] )

      tod_addr = [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], tund_info[ :dst_addr ] ].join

      if @alias_senders[ tod_addr ] && @alias_senders[ tod_addr ] == tund
        @alias_senders.delete( tod_addr )
      end

      dto_addr = [ tund_info[ :dst_addr ], tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join

      if @receivers[ dto_addr ] && @receivers[ dto_addr ] == tund
        @receivers.delete( dto_addr )
      end

      to_addr = [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ] ].join

      if @orig_tunds[ to_addr ] && @orig_tunds[ to_addr ] == tund
        @orig_tunds.delete( to_addr )
      end
    end

    def new_a_tund( tun_addr, tun_ip_addr, orig_src_addr, dst_addr )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_port = tund.local_address.ip_unpack.last

      @tunds[ tun_addr ] = tund
      @tund_infos[ tund ] = {
        port: tund_port,
        tun_addr: tun_addr,
        tun_ip_addr: tun_ip_addr,
        orig_src_addr: orig_src_addr,
        dst_addr: dst_addr,
        wbuffs: [],
        wmems: [],
        other_dst_rbuffs: {},
        receivers: {},
        last_traff_at: Time.new
      }

      @roles[ tund ] = :tund
      @reads << tund

      to_addr = [ tun_ip_addr, orig_src_addr ].join

      unless @orig_tunds.include?( to_addr )
        @orig_tunds[ to_addr ] = tund
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
                @ctlw.write( tund_info[ :tun_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
