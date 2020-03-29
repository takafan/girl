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
      @tunds = {}             # tund_port => tund
      @tund_infos = {}        # tund => {}
                              #   port: port
                              #   tun_addr: sockaddr
                              #   orgin_addr: sockaddr
                              #   dest_addr: sockaddr
                              #   orig_tund: tund1
                              #   wbuffs: []
                              #   new_dest_rbuffs: { new_dest_addr => [] }
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
            write_tund( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      tund_port = ctlr.read( 2 ).unpack( 'n' ).first
      tund = @tunds[ tund_port ]

      if tund
        add_closing( tund )
      end
    end

    def read_udpd( udpd )
      # src_addr(16) dest_addr(16)
      data, addrinfo, rflags, *controls = udpd.recvmsg
      tun_addr = addrinfo.to_sockaddr
      orig_addr = data[ 0, 16 ]
      dest_addr = data[ 16, 16 ]

      return unless Addrinfo.new( orig_addr ).ipv4?
      return unless Addrinfo.new( dest_addr ).ipv4?

      tund = @tunds[ [ tun_addr, orig_addr, dest_addr ].join ]

      unless tund
        tund = new_a_tund( tun_addr, orig_addr, dest_addr )
      end

      tund_info = @tund_infos[ tund ]
      tund_port = tund_info[ :port ]

      # puts "debug send 1 #{ tund_port }"
      msg = [ 1, tund_port ].pack( 'Cn' )
      @udpd.sendmsg( msg, 0, tun_addr )
    end

    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      from_addr = addrinfo.to_sockaddr
      tund_info = @tund_infos[ tund ]
      tund_info[ :last_traff_at ] = Time.new

      if tund_info[ :tun_addr ].nil?
        tund_info[ :tun_addr ] = from_addr

        # tund接到tun，找:orig_tund的:new_dest_rbuffs里来自dest_addr的流量，放进tund的:wbuffs
        orig_tund = tund_info[ :orig_tund ]

        if orig_tund
          orig_tund_info = @tund_infos[ orig_tund ]
          dest_rbuffs = orig_tund_info[ :new_dest_rbuffs ].delete( tund_info[ :dest_addr ] )

          if dest_rbuffs
            tund_info[ :wbuffs ] = dest_rbuffs
            add_write( tund )
          end
        end

        send_dest( tund, data )
      elsif from_addr == tund_info[ :tun_addr ]
        send_dest( tund, data )
      elsif from_addr == tund_info[ :dest_addr ]
        add_write( tund, data )
      else
        # 新的dest，把流量存在:new_dest_rbuffs里，并对应创建一对tun-tund
        new_dest_addr = from_addr

        unless tund_info[ :new_dest_rbuffs ].include?( new_dest_addr )
          tund_info[ :new_dest_rbuffs ][ new_dest_addr ] = []
        end

        tund_info[ :new_dest_rbuffs ][ new_dest_addr ] << data

        # puts "debug send 2 (a new dest coming) -> new_dest_addr(16) #{ addrinfo.inspect }"
        msg = [ [ 2 ].pack( 'C' ), new_dest_addr ].join
        @udpd.sendmsg( msg, 0, tund_info[ :tun_addr ] )
      end
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
      @tunds.delete( tund_info[ :port ] )
    end

    def new_a_tund( tun_addr, orig_addr, dest_addr, orig_tund = nil )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_port = tund.local_address.ip_unpack.last

      @tunds[ tund_port ] = tund
      @tund_infos[ tund ] = {
        port: tund_port,
        tun_addr: tun_addr,
        orig_addr: orig_addr,
        dest_addr: dest_addr,
        orig_tund: orig_tund,
        wbuffs: [],
        new_dest_rbuffs: {},
        last_traff_at: Time.new
      }

      @roles[ tund ] = :tund
      @reads << tund

      tund
    end

    def send_dest( tund, data )
      tund_info = @tund_infos[ tund ]
      orig_tund = tund_info[ :orig_tund ] || tund
      orig_tund.sendmsg( data, 0, tund_info[ :dest_addr ] )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @tund_infos.values.each do | tund_info |
              if now - tund_info[ :last_traff_at ] > 1800
                @ctlw.write( [ tund_info[ :port ] ].pack( 'n' ) )
              end
            end
          end
        end
      end
    end

  end
end
