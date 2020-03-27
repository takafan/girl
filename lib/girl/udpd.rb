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
        ctlr => :ctlr, # :ctlr / :udpd / :tund
        udpd => :udpd
      }
      @tunds = {}       # usd_addr => tund
      @tund_infos = {}  # tund => {}
                        #   usd_addr: [ udp_addr, src_addr, dest_addr ].join
                        #   udp_addr: udp_addr
                        #   src_addr: src_addr
                        #   tun_addr: sockaddr
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
      usd_addr = ctlr.read( 48 )
      tund = @tunds[ usd_addr ]

      if tund
        add_closing( tund )
      end
    end

    def read_udpd( udpd )
      data, addrinfo, rflags, *controls = udpd.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when 1
        # puts "debug got 1 req a tund -> src_addr dest_addr"
        udp_addr = addrinfo.to_sockaddr
        src_addr = data[ 1, 16 ]
        dest_addr = data[ 17, 16 ]

        return unless Addrinfo.new( src_addr ).ipv4?
        return unless Addrinfo.new( dest_addr ).ipv4?

        usd_addr = [ udp_addr, src_addr, dest_addr ].join
        tund = @tunds[ usd_addr ]

        unless tund
          tund = new_a_tund( udp_addr, src_addr, dest_addr )
        end

        tund_port = tund.local_address.ip_unpack.last

        # puts "debug send C: 2 tund port -> src_addr dest_addr -> n: tund_port #{ tund_port }"
        msg = [ [ 2 ].pack( 'C' ), src_addr, dest_addr, [ tund_port ].pack( 'n' ) ].join
        @udpd.sendmsg( msg, 0, udp_addr )
      end
    end

    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      from_addr = addrinfo.to_sockaddr
      tund_info = @tund_infos[ tund ]
      tund_info[ :last_traff_at ] = Time.new

      unless tund_info[ :tun_addr ]
        if addrinfo.ip_address != Addrinfo.new( tund_info[ :udp_addr ] ).ip_address
          return
        end

        tund_info[ :tun_addr ] = from_addr

        if data.unpack( 'C' ).first == 4 && tund_info[ :wbuffs ].any?
          # puts "debug got C: 4 hello i'm new tun"
          add_write( tund )
          return
        end
      end

      if from_addr == tund_info[ :tun_addr ]
        tund.sendmsg( data, 0, tund_info[ :dest_addr ] )
      elsif from_addr == tund_info[ :dest_addr ]
        add_write( tund, data )
      else
        udp_addr = tund_info[ :udp_addr ]
        src_addr = tund_info[ :src_addr ]
        new_dest_addr = from_addr
        usd_addr = [ udp_addr, src_addr, new_dest_addr ].join
        new_tund = @tunds[ usd_addr ]

        if new_tund
          puts "conflict dest addr? #{ addrinfo.inspect } vs #{ Addrinfo.new( udp_addr ).inspect } #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( tund_info[ :dest_addr ] ).inspect }"
          return
        end

        new_tund = new_a_tund( udp_addr, src_addr, new_dest_addr )
        new_tund_port = new_tund.local_address.ip_unpack.last

        # puts "debug send C: 3 req a new tun -> src_addr new_dest_addr -> new_tund_port #{ addrinfo.inspect } #{ new_tund_port }"
        msg = [ [ 3 ].pack( 'C' ), src_addr, new_dest_addr, [ new_tund_port ].pack( 'n' ) ].join
        @udpd.sendmsg( msg, 0, udp_addr )

        add_write( new_tund, data )
      end
    end

    def write_udpd( udpd )
      if @udpd_wbuffs.empty?
        @writes.delete( udpd )
        return
      end

      udp_addr, data = @udpd_wbuffs.shift
      @udpd.sendmsg( data, 0, udp_addr )
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
    end

    def add_write( tund, data = nil )
      tund_info = @tund_infos[ tund ]

      if data
        tund_info[ :wbuffs ] << data
      end

      if tund_info[ :tun_addr ] && !@writes.include?( tund )
        @writes << tund
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
      @tunds.delete( tund_info[ :usd_addr ] )
    end

    def new_a_tund( udp_addr, src_addr, dest_addr )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      usd_addr = [ udp_addr, src_addr, dest_addr ].join
      @tunds[ usd_addr ] = tund
      @tund_infos[ tund ] = {
        usd_addr: usd_addr,
        udp_addr: udp_addr,
        src_addr: src_addr,
        dest_addr: dest_addr,
        wbuffs: [],
        tun_addr: nil,
        last_traff_at: Time.new
      }

      @roles[ tund ] = :tund
      @reads << tund

      tund
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @tund_infos.values.each do | tund_info |
              if now - tund_info[ :last_traff_at ] > 1800
                @ctlw.write( tund_info[ :usd_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
