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
        redir => :redir,
        udp => :udp
      }
      @orig_tuns = {} # orig_addr => tun
      @tuns = {}      # [ orig_addr, dest_addr ].join => tun
      @tun_infos = {} # tun => {}
                      #   orig_addr: sockaddr
                      #   dest_addr: sockaddr
                      #   tund_addr: sockaddr
                      #   orig_tun: tun1 一个源地址发往第二个目的地，衍生出tun2-tund2中转流量，但由tund1发往第二个目的地，由tun1发往源地址
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
      od_addr = ctlr.read( 32 )
      tun = @tuns[ od_addr ]

      if tun
        add_closing( tun )
      end
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      orig_addr = addrinfo.to_sockaddr
      orig_tun = nil

      # puts "debug redir recv from #{ addrinfo.inspect }"
      bin = IO.binread( '/proc/net/nf_conntrack' )
      rows = bin.split( "\n" ).reverse.map { | line | line.split( ' ' ) }
      row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 5 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 7 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port && _row[ 9 ] == '[UNREPLIED]' }

      unless row
        row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 5 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 9 ] == '[UNREPLIED]' && _row[ 13 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port }

        unless row
          puts "miss conntrack? #{ addrinfo.inspect } #{ Time.new }"
          IO.binwrite( '/tmp/nf_conntrack', bin )
          return
        end

        src_ip = row[ 5 ].split( '=' )[ 1 ]
        src_port = row[ 7 ].split( '=' )[ 1 ].to_i
        orig_addr = Socket.sockaddr_in( src_ip, src_port )
        orig_tun = @orig_tuns[ orig_addr ]

        unless orig_tun
          puts "a chain src #{ addrinfo.inspect } coming, miss orig? #{ Time.new }"
          return
        end
      end

      dest_ip = row[ 6 ].split( '=' )[ 1 ]
      dest_port = row[ 8 ].split( '=' )[ 1 ].to_i
      dest_addr = Socket.sockaddr_in( dest_port, dest_ip )
      od_addr = [ orig_addr, dest_addr ].join
      tun = @tuns[ od_addr ]

      unless tun
        tun = new_a_tun( orig_addr, dest_addr, orig_tun )

        # puts "debug tun > udpd: #{ Addrinfo.new( orig_addr ).inspect } #{ Addrinfo.new( dest_addr ).inspect }"
        tun.sendmsg( od_addr, 0, @udpd_addr )
      end

      tun_info = @tun_infos[ tun ]
      add_write( tun, data )
    end

    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      # puts "debug tun recv from #{ addrinfo.inspect }"
      from_addr = addrinfo.to_sockaddr
      tun_info = @tun_infos[ tun ]
      tun_info[ :last_traff_at ] = Time.new

      if from_addr == @udpd_addr
        ctl_num = data[ 0 ].unpack( 'C' ).first

        case ctl_num
        when 1 # (tund ready) -> n: tund_port
          tund_port = data[ 1, 2 ].unpack( 'n' ).first
          tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )

          unless tun_info[ :tund_addr ]
            tun_info[ :tund_addr ] = tund_addr
            # now tun can flush wbuffs to tund
            add_write( tun )
          end
        when 2 # (a new dest coming) -> new_dest_addr(16)
          new_dest_addr = data[ 1, 16 ]
          orig_addr = tun_info[ :orig_addr ]
          new_tun = @tuns[ [ orig_addr, new_dest_addr ].join ]

          unless new_tun
            unless  @orig_tuns.include?( orig_addr )
              puts "a new dest #{ Addrinfo.new( new_dest_addr ).inspect } coming, but tun is not orig? #{ Time.new }"
              return
            end

            new_tun = new_a_tun( orig_addr, new_dest_addr, tun )
          end

          new_tun.sendmsg( [ orig_addr, new_dest_addr ], 0, @udpd_addr )
        end
      elsif from_addr == tun_info[ :tund_addr ]
        # puts "debug tun > #{ Addrinfo.new( tun_info[ :orig_addr ] ).inspect }"
        orig_tun = tun_info[ :orig_tun ] || tun
        orig_tun.sendmsg( data, 0, tun_info[ :orig_addr ] )
      elsif from_addr == tun_info[ :orig_addr ]
        add_write( tun, data )
      end
    end

    def write_tun( tun )
      if @closings.include?( tun )
        close_tun( tun )
        return
      end

      tun_info = @tun_infos[ tun ]

      if tun_info[ :wbuffs ].empty?
        @writes.delete( tun )
        return
      end

      data = tun_info[ :wbuffs ].shift
      # puts "debug tun > #{ Addrinfo.new( tun_info[ :tund_addr ] ).inspect }"
      tun.sendmsg( data, 0, tun_info[ :tund_addr ] )
    end

    def add_write( tun, data = nil )
      tun_info = @tun_infos[ tun ]

      if data
        tun_info[ :wbuffs ] << data
      end

      if tun_info[ :tund_addr ] && !@writes.include?( tun )
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
      @tuns.delete( [ tun_info[ :orig_addr ], tun_info[ :dest_addr ] ].join )

      unless tun_info[ :ogin_tun ]
        @orig_tuns.delete( tun_info[ :orig_addr ] )
      end
    end

    def new_a_tun( orig_addr, dest_addr, orig_tun )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      unless orig_tun
        @orig_tuns[ orig_addr ] = tun
      end

      @tuns[ [ orig_addr, dest_addr ].join ] = tun
      @tun_infos[ tun ] = {
        orig_addr: orig_addr,
        dest_addr: dest_addr,
        tund_addr: tund_addr,
        orig_tun: orig_tun,
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
                @ctlw.write( [ tun_info[ :orig_addr ], tun_info[ :dest_addr ] ].join )
              end
            end
          end
        end
      end
    end

  end
end
