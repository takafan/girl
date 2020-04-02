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
      @tunds = {}             # [ tun_ip_addr orig_src_addr dest_addr ] => tund
      @tund_infos = {}        # tund => {}
                              #   port: port
                              #   is_tunneled: false
                              #   tun_addr: sockaddr
                              #   tun_ip_addr: sockaddr
                              #   orig_src_addr: sockaddr
                              #   dest_addr: sockaddr
                              #   root_tund: tund1
                              #   wbuffs: []
                              #   is_dest_responsed: false
                              #   dest_wmemos: []
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
      tod_addr = ctlr.read( 48 )
      tund = @tunds[ tod_addr ]

      if tund
        add_closing( tund )
      end
    end

    def read_udpd( udpd )
      # C: 1 (tun > udpd: req a tund) -> orig_src_addr -> dest_addr
      # C: 4 (tun > udpd: req a chain tund) -> orig_src_addr -> dest_addr -> root_dest_addr
      data, addrinfo, rflags, *controls = udpd.recvmsg
      # puts "debug udpd recv #{ data.inspect } from #{ addrinfo.inspect }"
      ctl_num = data[ 0 ].unpack( 'C' ).first
      orig_src_addr = data[ 1, 16 ]
      dest_addr = data[ 17, 16 ]
      tun_addr = addrinfo.to_sockaddr
      tun_ip_addr = Addrinfo.ip( addrinfo.ip_address ).to_sockaddr

      return unless [ 1, 4 ].include?( ctl_num )
      return unless Addrinfo.new( orig_src_addr ).ipv4?
      return unless Addrinfo.new( dest_addr ).ipv4?

      tund = @tunds[ [ tun_ip_addr, orig_src_addr, dest_addr ].join ]

      if ctl_num == 1
        unless tund
          tund = new_a_tund( tun_addr, tun_ip_addr, orig_src_addr, dest_addr )
        end
      elsif ctl_num == 4
        root_dest_addr = data[ 33, 16 ]
        return unless Addrinfo.new( root_dest_addr ).ipv4?

        root_tund = @tunds[ [ tun_ip_addr, orig_src_addr, root_dest_addr ].join ]

        unless root_tund
          puts "miss root tund? #{ Addrinfo.new( tun_ip_addr ).inspect } #{ Addrinfo.new( orig_src_addr ).inspect } #{ Addrinfo.new( root_dest_addr ).inspect }"
          return
        end

        if tund
          tund_info = @tund_infos[ tund ]
          tund_info[ :root_tund ] = root_tund
        else
          tund = new_a_tund( tun_addr, tun_ip_addr, orig_src_addr, dest_addr, root_tund )
        end
      end

      tund_info = @tund_infos[ tund ]
      tund_port = tund_info[ :port ]

      # puts "debug send C: 2 (udpd > tun: tund port) -> n: tund_port -> tun_addr #{ tund_port } #{ addrinfo.inspect }"
      @udpd_wbuffs << [ tun_addr, [ [ 2, tund_port ].pack( 'Cn' ), tun_addr ].join ]

      unless @writes.include?( udpd )
        @writes << udpd
      end
    end

    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      from_addr = addrinfo.to_sockaddr
      tund_info = @tund_infos[ tund ]
      tund_info[ :last_traff_at ] = Time.new

      if from_addr == tund_info[ :tun_addr ]
        root_tund = tund_info[ :root_tund ]

        if !tund_info[ :is_tunneled ]
          tund_info[ :is_tunneled ] = true

          if root_tund
            # p2p tunnel paired
            root_tund_info = @tund_infos[ root_tund ]
            dest_rbuffs = root_tund_info[ :new_dest_rbuffs ].delete( tund_info[ :dest_addr ] )

            if dest_rbuffs
              # puts "debug #{ Addrinfo.new( tund_info[ :dest_addr ] ).inspect } dest_rbuffs #{ dest_rbuffs.inspect }"
              tund_info[ :wbuffs ] = dest_rbuffs
              add_write( tund )
            end

            if data.size == 1 && data[ 0 ].unpack( 'C' ).first == 5
              puts "ignore C: 5 (hello) #{ Time.new }"
              return
            end
          end
        end

        sender = root_tund || tund
        sender.sendmsg( data, 0, tund_info[ :dest_addr ] )

        if root_tund.nil? && !tund_info[ :is_dest_responsed ]
          if tund_info[ :dest_wmemos ].size >= 10
            tund_info[ :dest_wmemos ].clear
          end

          tund_info[ :dest_wmemos ] << data
        end
      elsif from_addr == tund_info[ :dest_addr ]
        tund_info[ :is_dest_responsed ] = true
        add_write( tund, data )
      else
        # p2p input
        # puts "debug tund recv #{ data.inspect } from #{ Addrinfo.new( from_addr ).inspect }"
        chain_tund = @tunds[ [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], from_addr ].join ]

        unless chain_tund
          unless tund_info[ :new_dest_rbuffs ].include?( from_addr )
            tund_info[ :new_dest_rbuffs ][ from_addr ] = []
          end

          tund_info[ :new_dest_rbuffs ][ from_addr ] << data

          # puts "debug send C: 3 (udpd > tun: req a chain tun) -> new_dest_addr -> root_dest_addr #{ Addrinfo.new( from_addr ).inspect } #{ Addrinfo.new( tund_info[ :dest_addr ] ).inspect }"
          msg = [ [ 3 ].pack( 'C' ), from_addr, tund_info[ :dest_addr ] ].join
          @udpd.sendmsg( msg, 0, tund_info[ :tun_addr ] )
          return
        end

        chain_tund_info = @tund_infos[ chain_tund ]

        unless chain_tund_info[ :root_tund ]
          # p2p paired
          chain_tund_info[ :root_tund ] = tund

          if chain_tund_info[ :dest_wmemos ].size > 0
            chain_tund_info[ :dest_wmemos ].each do | wmemo |
              # puts "debug send wmemo #{ wmemo.inspect } to #{ Addrinfo.new( from_addr ).inspect }"
              tund.sendmsg( wmemo, 0, from_addr )
            end

            chain_tund_info[ :dest_wmemos ].clear
          end
        end

        add_write( chain_tund, data )
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
      @tunds.delete( [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], tund_info[ :dest_addr ] ].join )
    end

    def new_a_tund( tun_addr, tun_ip_addr, orig_src_addr, dest_addr, root_tund = nil )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_port = tund.local_address.ip_unpack.last

      @tunds[ [ tun_ip_addr, orig_src_addr, dest_addr ].join ] = tund
      @tund_infos[ tund ] = {
        port: tund_port,
        is_tunneled: false,
        tun_addr: tun_addr,
        tun_ip_addr: tun_ip_addr,
        orig_src_addr: orig_src_addr,
        dest_addr: dest_addr,
        root_tund: root_tund,
        wbuffs: [],
        is_dest_responsed: root_tund ? true : false,
        dest_wmemos: [],
        new_dest_rbuffs: {},
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
                @ctlw.write(  [ tund_info[ :tun_ip_addr ], tund_info[ :orig_src_addr ], tund_info[ :dest_addr ] ].join )
              end
            end
          end
        end
      end
    end

  end
end
