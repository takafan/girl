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
# C: 1 (tun > udpd: req a tund) -> src_addr dest_addr
# C: 2 (udpd > tun: tund port) -> n: tund_port
# C: 3 (udpd > tun: req a chain tun) -> new_dest_addr orig_tun_addr
# C: 4 (tun > udpd: req a chain tund) -> src_addr dest_addr orig_tun_addr
# C: 5 (tun > tund: hello)
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
        ctlr => :ctlr, # :ctlr / :redir / :tun
        redir => :redir
      }
      @tuns = {}      # [ src_addr dest_addr ] => tun
      @tun_infos = {} # tun => {}
                      #   src_addr: sockaddr
                      #   dest_addr: sockaddr
                      #   tund_addr: sockaddr
                      #   is_chain: false
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
            write_tun( sock )
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

      unless tun
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
        when 2 # C: 2 (udpd > tun: tund port) -> n: tund_port
          return if tun_info[ :tund_addr ]

          tund_port = data[ 1, 2 ].unpack( 'n' ).first
          tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )
          tun_info[ :tund_addr ] = tund_addr

          # now tun can flush wbuffs to tund, if empty, just send a (5: hello) to cross nat, tund should ignore hello
          if tun_info[ :wbuffs ].empty?
            tun_info[ :wbuffs ] << [ 5 ].pack( 'C' )
          end

          add_write( tun )
        when 3 # C: 3 (udpd > tun: req a chain tun) -> new_dest_addr orig_tun_addr
          new_dest_addr = data[ 1, 16 ]
          orig_tun_addr = data[ 17, 16 ]
          src_addr = tun_info[ :src_addr ]
          chain_tun = @tuns[ [ src_addr, new_dest_addr ].join ]

          unless chain_tun
            chain_tun = new_a_tun( src_addr, new_dest_addr, is_chain = true )
          end

          # puts "debug send C: 4 (tun > udpd: req a chain tund) -> src_addr dest_addr orig_tun_addr #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( new_dest_addr ).inspect } #{ Addrinfo.new( orig_tun_addr ).inspect }"
          ctlmsg = [ [ 4 ].pack( 'C' ), src_addr, new_dest_addr, orig_tun_addr ].join
          add_ctlmsg( chain_tun, ctlmsg )
        end
      elsif from_addr == tun_info[ :tund_addr ]
        orig_tun = tun_info[ :is_chain ] ? tun : @redir
        orig_tun.sendmsg( data, 0, tun_info[ :src_addr ] )
      elsif from_addr == tun_info[ :src_addr ]
        add_write( tun, data )
      end
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
    end

    def new_a_tun( src_addr, dest_addr, is_chain = false )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      @tuns[ [ src_addr, dest_addr ].join ] = tun
      @tun_infos[ tun ] = {
        src_addr: src_addr,
        dest_addr: dest_addr,
        tund_addr: nil,
        is_chain: is_chain,
        ctlmsgs: [],
        wbuffs: [],
        last_traff_at: Time.new
      }

      @roles[ tun ] = :tun
      @reads << tun

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
