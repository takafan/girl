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
# iptables -t nat -A PREROUTING -p udp -d game.server.ip -j REDIRECT --to-ports 1313
#
# C: 1 req a tund -> src_addr dest_addr
# C: 2 tund port -> src_addr dest_addr -> n: tund_port
# C: 3 req a new tun -> src_addr new_dest_addr -> n: tund_port
# C: 4 hello i'm new tun
#
module Girl
  class Udp

    def initialize( udpd_host, udpd_port = 3030, redir_port = 1313 )
      ctlr, ctlw = IO.pipe

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      puts "redir bound on #{ redir_port } #{ Time.new }"

      udp = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udp.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udp.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      puts "udp bound on #{ udp.local_address.ip_unpack.last } #{ Time.new }"

      @mutex = Mutex.new
      @udpd_host = udpd_host
      @udpd_addr = Socket.sockaddr_in( udpd_port, udpd_host )
      @ctlw = ctlw
      @redir = redir
      @udp = udp
      @reads = [ ctlr, redir, udp ]
      @writes = []
      @closings = []
      @roles = {
        ctlr => :ctlr, # :ctlr / :redir / :udp / :tun
        redir => :redir,
        udp => :udp
      }
      @tuns = {}         # sd_addr => tun
      @tun_infos = {}    # tun => {}
                         #   sd_addr: [ src_addr, dest_addr ].join
                         #   src_addr: sockaddr
                         #   dest_addr: sockaddr
                         #   tund_addr: sockaddr
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
      # puts "debug redir recv from #{ addrinfo.inspect }"
      bin = IO.binread( '/proc/net/nf_conntrack' )
      rows = bin.split( "\n" ).reverse.map { | line | line.split( ' ' ) }
      row = rows.find { | _row | _row[ 2 ] == 'udp' && _row[ 5 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 7 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port && _row[ 9 ] == '[UNREPLIED]' }

      unless row
        puts "miss #{ addrinfo.inspect } #{ Time.new }"
        IO.binwrite( '/tmp/nf_conntrack', bin )
        return
      end

      src_addr = addrinfo.to_sockaddr
      dest_addr = Socket.sockaddr_in( row[ 8 ].split( '=' )[ 1 ].to_i, row[ 6 ].split( '=' )[ 1 ] )
      sd_addr = [ src_addr, dest_addr ].join
      tun = @tuns[ sd_addr ]

      unless tun
        tun = new_a_tun( src_addr, dest_addr )

        # puts "debug send C: 1 req a tund -> src_addr dest_addr #{ addrinfo.inspect } #{ Addrinfo.new( dest_addr ).inspect }"
        msg = [ [ 1 ].pack( 'C' ), sd_addr ].join
        @udp.sendmsg( msg, 0, @udpd_addr )
      end

      tun_info = @tun_infos[ tun ]
      add_write( tun, data )
    end

    def read_udp( udp )
      data, addrinfo, rflags, *controls = udp.recvmsg
      # puts "debug udp recv from #{ addrinfo.inspect }"
      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when 2
        # puts "debug got 2 tund port -> src_addr dest_addr -> n: tund_port"
        sd_addr = data[ 1, 32 ]
        tun = @tuns[ sd_addr ]
        return unless tun

        tun_info = @tun_infos[ tun ]

        unless tun_info[ :tund_addr ]
          tund_port = data[ 33, 2 ].unpack( 'n' ).first
          tun_info[ :tund_addr ] = Socket.sockaddr_in( tund_port, @udpd_host )
          add_write( tun )
        end
      when 3
        # puts "debug got 3 req a new tun -> src_addr new_dest_addr -> n: tund_port"
        sd_addr = data[ 1, 32 ]
        tun = @tuns[ sd_addr ]
        return if tun

        src_addr = sd_addr[ 0, 16 ]
        dest_addr = sd_addr[ 16, 16 ]
        tund_port = data[ 33, 2 ].unpack( 'n' ).first
        tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )
        tun = new_a_tun( src_addr, dest_addr )
        tun_info = @tun_infos[ tun ]
        tun_info[ :tund_addr ] = tund_addr

        # puts "debug send C: 4 hello i'm new tun"
        msg = [ 4 ].pack( 'C' )
        add_write( tun, msg )
      end

    end

    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      # puts "debug tun recv from #{ addrinfo.inspect }"
      from_addr = addrinfo.to_sockaddr
      tun_info = @tun_infos[ tun ]
      tun_info[ :last_traff_at ] = Time.new

      if from_addr == tun_info[ :tund_addr ]
        # puts "debug tun send to #{ Addrinfo.new( tun_info[ :src_addr ] ).inspect }"
        tun.sendmsg( data, 0, tun_info[ :src_addr ] )
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

      if tun_info[ :wbuffs ].empty?
        @writes.delete( tun )
        return
      end

      data = tun_info[ :wbuffs ].shift
      # puts "debug tun send to #{ Addrinfo.new( tun_info[ :tund_addr ] ).inspect }"
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
      @tuns.delete( tun_info[ :sd_addr ] )
    end

    def new_a_tun( src_addr, dest_addr )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      sd_addr = [ src_addr, dest_addr ].join
      @tuns[ sd_addr ] = tun
      @tun_infos[ tun ] = {
        sd_addr: sd_addr,
        src_addr: src_addr,
        dest_addr: dest_addr,
        wbuffs: [],
        tund_addr: nil,
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
                @ctlw.write( tun_info[ :sd_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
