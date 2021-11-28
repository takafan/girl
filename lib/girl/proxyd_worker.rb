module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port, nameserver )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @roles = {}                     # sock => :dotr / :ctld / :ctl / :infod / :dst / :tund / :tun / :dns
      @ctl_infos = {}                 # im => { :ctl_addr, :ctld, :tunds }
      @tund_infos = {}                # tund => { :im }
      @resolv_caches = {}             # domain => [ ip, created_at ]
      @dst_infos = ConcurrentHash.new # dst => { :dst_id, :im, :domain, :rbuff, :tun, :wbuff, :src_id,
                                      #          :created_at, :connected, :last_add_wbuff_at, :closing_write, :closing, :paused }
      @tun_infos = ConcurrentHash.new # tun => { :im, :dst, :domain, :rbuff, :wbuff, :created_at, :last_add_wbuff_at, :closing, :paused }
      @dns_infos = {}                 # dns => { :im, :src_id, :domain, :port, :closing }
      @traffs = ConcurrentHash.new    # im => { :in, :out }
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )

      new_a_pipe
      new_ctlds( proxyd_port )
      new_a_infod( infod_port )
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_expire
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dotr then
            read_dotr( sock )
          when :dns then
            read_dns( sock )
          when :ctld then
            read_ctld( sock )
          when :infod then
            read_infod( sock )
          when :dst then
            read_dst( sock )
          when :tund then
            read_tund( sock )
          when :tun then
            read_tun( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :dst then
            write_dst( sock )
          when :tun then
            write_tun( sock )
          else
            puts "#{ Time.new } write unknown role #{ role }"
            close_sock( sock )
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    ##
    # quit!
    #
    def quit!
      # puts "debug exit"
      exit
    end

    private

    ##
    # add dst rbuff
    #
    def add_dst_rbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ]
      dst_info[ :rbuff ] << data

      if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        puts "#{ Time.new } dst rbuff full"
        close_dst( dst )
      end
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ]
      dst_info[ :wbuff ] << data
      dst_info[ :last_add_wbuff_at ] = Time.new
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        tun = dst_info[ :tun ]

        if tun then
          tun_info = @tun_infos[ tun ]

          if tun_info then
            puts "#{ Time.new } pause tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ].inspect }"
            @reads.delete( tun )
            tun_info[ :paused ] = true
          end
        end
      end
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end
    end

    ##
    # add tun wbuff
    #
    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing ]
      tun_info[ :wbuff ] << data
      tun_info[ :last_add_wbuff_at ] = Time.new
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = tun_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
    end

    ##
    # close dns
    #
    def close_dns( dns )
      return if dns.nil? || dns.closed?
      close_sock( dns )
      @dns_infos.delete( dns )
    end

    ##
    # close dst
    #
    def close_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )

      if dst_info then
        close_tun( dst_info[ :tun ] )
      end
    end

    ##
    # close dsts
    #
    def close_dsts( im )
      @dst_infos.select{ | _, info | info[ :im ] == im }.keys.each{ | dst | close_dst( dst ) }
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @writes.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
      end
    end

    ##
    # close read tun
    #
    def close_read_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close read tun"
      tun.close_read
      @reads.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @writes.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
      end
    end

    ##
    # close sock
    #
    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    ##
    # close tun
    #
    def close_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      @tun_infos.delete( tun )
    end

    ##
    # close tund
    #
    def close_tund( tund )
      return if tund.nil? || tund.closed?
      # puts "debug close tund"
      close_sock( tund )
      @tund_infos.delete( tund )
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @reads.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
      end
    end

    ##
    # close write tun
    #
    def close_write_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close write tun"
      tun.close_write
      @writes.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @reads.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
      end
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL
          now = Time.new

          @dst_infos.select{ | dst, info | !dst.closed? && info[ :connected ] && ( now - ( info[ :last_add_wbuff_at ] || info[ :created_at ] ) >= EXPIRE_AFTER ) }.values.each do | dst_info |
            puts "#{ Time.new } expire dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
            dst_info[ :closing ] = true
            next_tick
          end

          @tun_infos.select{ | tun, info | !tun.closed? && ( now - ( info[ :last_add_wbuff_at ] || info[ :created_at ] ) >= EXPIRE_AFTER ) }.values.each do | tun_info |
            puts "#{ Time.new } expire tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ].inspect }"
            tun_info[ :closing ] = true
            next_tick
          end
        end
      end
    end

    ##
    # loop check traff
    #
    def loop_check_traff
      if RESET_TRAFF_DAY > 0 then
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL

            if Time.new.day == RESET_TRAFF_DAY then
              puts "#{ Time.new } reset traffs"
              @traffs.each{ | im, info | info[ :in ] = info[ :out ] = 0 }
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
      return if ctld.nil? || ctld.closed?

      begin
        dst = Socket.new( ipaddr.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ im.inspect } #{ domain.inspect } #{ port } #{ e.class }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      ip = ipaddr.to_s
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect destination #{ im.inspect } #{ domain.inspect } #{ ip } #{ port } #{ e.class }"
        dst.close
        return
      end

      dst_id = rand( ( 2 ** 64 ) - 2 ) + 1

      dst_info = {
        dst_id: dst_id,         # dst_id
        im: im,                 # 标识
        domain: domain,         # 目的地
        rbuff: '',              # 对应的tun没准备好，暂存读到的流量
        tun: nil,               # 对应的tun
        wbuff: '',              # 从tun读到的流量
        src_id: src_id,         # 近端src id
        created_at: Time.new,   # 创建时间
        connected: false,       # 是否已连接
        last_add_wbuff_at: nil, # 上一次加写前的时间
        closing_write: false,   # 准备关闭写
        closing: false,         # 准备关闭
        paused: false           # 已暂停
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      add_write( dst )

      data = [ PAIRED, src_id, dst_id ].pack( 'CQ>Q>' )
      # puts "debug add ctlmsg paired #{ im.inspect } #{ src_id } #{ dst_id }"
      send_ctlmsg( ctld, data, ctl_addr )

      Thread.new do
        sleep EXPIRE_CONNECTING

        if dst && !dst.closed? && !dst_info[ :connected ] then
          puts "#{ Time.new } expire dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
          dst_info[ :closing ] = true
          next_tick
        end
      end
    end

    ##
    # new a infod
    #
    def new_a_infod( infod_port )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( Socket.sockaddr_in( infod_port, '127.0.0.1' ) )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
    end

    ##
    # new a pipe
    #
    def new_a_pipe
      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
    end

    ##
    # new a tund
    #
    def new_a_tund
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund.listen( 127 )
      tund
    end

    ##
    # new ctlds
    #
    def new_ctlds( begin_port )
      10.times do | i |
        ctld_port = begin_port + i
        ctld = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        ctld.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        ctld.bind( Socket.sockaddr_in( ctld_port, '0.0.0.0' ) )
        puts "#{ Time.new } ctld bind on #{ ctld_port }"
        add_read( ctld, :ctld )
      end
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # pack a chunk
    #
    def pack_a_chunk( data )
      data = @custom.encode( data )
      "#{ [ data.bytesize ].pack( 'n' ) }#{ data }"
    end

    ##
    # resolve domain port
    #
    def resolve_domain_port( domain_port, src_id, im, ctld, ctl_addr )
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ipaddr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain.inspect } hit resolv cache #{ ipaddr.to_s }"
          new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
          return
        end

        # puts "debug expire #{ domain.inspect } resolv cache"
        @resolv_caches.delete( domain )
      end

      begin
        ipaddr = IPAddr.new( domain )

        if ipaddr.ipv4? || ipaddr.ipv6? then
          new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
          return
        end
      rescue Exception => e
      end

      begin
        packet = Net::DNS::Packet.new( domain )
      rescue Exception => e
        puts "#{ Time.new } new packet #{ e.class } #{ im.inspect } #{ domain.inspect }"
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain.inspect }"
        dns.sendmsg_nonblock( packet.data, 0, @nameserver_addr )
      rescue Exception => e
        puts "#{ Time.new } dns sendmsg #{ e.class } #{ im.inspect } #{ domain.inspect }"
        dns.close
        return
      end

      dns_info = {
        im: im,
        src_id: src_id,
        domain: domain,
        port: port,
        closing: false
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )

      Thread.new do
        sleep EXPIRE_NEW

        if dns && !dns.closed? && !dns_info[ :closing ] then
          # puts "debug expire dns #{ dns_info[ :domain ].inspect }"
          dns_info[ :closing ] = true
          next_tick
        end
      end
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( ctld, data, to_addr )
      return if ctld.nil? || ctld.closed?
      data = @custom.encode( data )

      begin
        ctld.sendmsg_nonblock( data, 0, to_addr )
      rescue Exception => e
        puts "#{ Time.new } ctld sendmsg #{ e.class }"
      end
    end

    ##
    # send tund ports
    #
    def send_tund_ports( ctl_info )
      tund_ports = ctl_info[ :tunds ].map{ | tund | tund.local_address.ip_port }
      puts "#{ Time.new } send tund ports #{ tund_ports.inspect }"
      data = [ TUND_PORTS, *tund_ports ].pack( 'Cn*' )
      send_ctlmsg( ctl_info[ :ctld ], data, ctl_info[ :ctl_addr ] )
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ] || dst_info[ :closing_write ]
      # puts "debug set dst closing write"
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set dst info tun
    #
    def set_dst_info_tun( dst_info, tun )
      dst_info[ :tun ] = tun
      # puts "debug add pong #{ dst_info[ :src_id ] }"
      data = [ dst_info[ :src_id ] ].pack( 'Q>' )

      until dst_info[ :rbuff ].empty? do
        chunk_data = dst_info[ :rbuff ][ 0, CHUNK_SIZE ]
        # puts "debug move dst rbuff to tun wbuff #{ chunk_data.bytesize }"
        data << pack_a_chunk( chunk_data )
        dst_info[ :rbuff ] = dst_info[ :rbuff ][ chunk_data.bytesize..-1 ]
      end

      add_tun_wbuff( tun, data )
    end

    ##
    # set tun closing write
    #
    def set_tun_closing_write( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing ] || tun_info[ :closing_write ]
      # puts "debug set tun closing write"
      tun_info[ :closing_write ] = true
      add_write( tun )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )
      @dns_infos.select{ | _, info | info[ :closing ] }.keys.each{ | dns | close_dns( dns ) }
      @dst_infos.select{ | _, info | info[ :closing ] }.keys.each{ | dst | close_dst( dst ) }
      @tun_infos.select{ | _, info | info[ :closing ] }.keys.each{ | tun | close_tun( tun ) }
    end

    ##
    # read dns
    #
    def read_dns( dns )
      if dns.closed? then
        puts "#{ Time.new } read dns but dns closed?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "#{ Time.new } dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      return if data.empty?

      # puts "debug recv dns #{ data.inspect }"
      dns_info = @dns_infos[ dns ]
      im = dns_info[ :im ]
      ctl_info = @ctl_infos[ im ]

      unless ctl_info then
        puts "#{ Time.new } read dns but ctl already closed #{ im.inspect }"
        close_dns( dns )
        return
      end

      begin
        packet = Net::DNS::Packet::parse( data )
      rescue Exception => e
        puts "#{ Time.new } parse packet #{ e.class }"
        close_dns( dns )
        return
      end

      ans = packet.answer.find{ | ans | ans.class == Net::DNS::RR::A }

      if ans then
        domain = dns_info[ :domain ]
        ipaddr = IPAddr.new( ans.value )
        @resolv_caches[ domain ] = [ ipaddr, Time.new ]
        src_id = dns_info[ :src_id ]
        port = dns_info[ :port ]
        new_a_dst( ipaddr, domain, port, src_id, im, ctl_info[ :ctld ], ctl_info[ :ctl_addr ] )
      end

      close_dns( dns )
    end

    ##
    # read ctld
    #
    def read_ctld( ctld )
      data, addrinfo, rflags, *controls = ctld.recvmsg
      return if data.empty?

      data = @custom.decode( data )
      ctl_num = data[ 0 ].unpack( 'C' ).first
      ctl_addr = addrinfo.to_sockaddr

      case ctl_num
      when HELLO then
        return if data.bytesize <= 1
        im = data[ 1..-1 ]
        result = @custom.check( im, addrinfo )

        if result != :success then
          puts "#{ Time.new } #{ result } #{ im.inspect } #{ addrinfo.inspect }"
          return
        end

        unless @traffs.include?( im ) then
          @traffs[ im ] = {
            in: 0,
            out: 0
          }
        end

        ctl_info = @ctl_infos[ im ]

        if ctl_info then
          ctl_info[ :ctl_addr ] = ctl_addr
          ctl_info[ :ctld ] = ctld
        else
          tunds = []

          10.times do
            tund = new_a_tund
            @tund_infos[ tund ] = { im: im }
            add_read( tund, :tund )
            tunds << tund
          end

          ctl_info = {
            ctl_addr: ctl_addr, # ctl地址
            ctld: ctld,         # 对应的ctld
            tunds: tunds,       # 对应tunds
          }

          @ctl_infos[ im ] = ctl_info
        end

        puts "#{ Time.new } got hello #{ im.inspect } #{ addrinfo.ip_unpack.inspect }"
        print "ctls #{ @ctl_infos.size } tunds #{ @tund_infos.size }"
        puts " dsts #{ @dst_infos.size } tuns #{ @tun_infos.size } dnses #{ @dns_infos.size }"
        send_tund_ports( ctl_info )
      when A_NEW_SOURCE then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        domain_port, im = data[ 9..-1 ].split( '/' )
        ctl_info = @ctl_infos[ im ]

        unless ctl_info then
          puts "#{ Time.new } got a new source but unknown im #{ im.inspect }"
          return
        end

        ctl_info[ :ctl_addr ] = ctl_addr
        ctl_info[ :ctld ] = ctld
        dst_info = @dst_infos.values.find{ | info | info[ :src_id ] == src_id }

        if dst_info then
          # puts "debug dst info exist, send ctlmsg paired #{ src_id } #{ dst_info[ :dst_id ] }"
          data2 = [ PAIRED, src_id, dst_info[ :dst_id ] ].pack( 'CQ>Q>' )
          send_ctlmsg( ctld, data2, ctl_addr )
          return
        end

        # puts "debug got a new source #{ src_id } #{ domain_port.inspect } #{ im.inspect } #{ addrinfo.ip_unpack.inspect }"
        resolve_domain_port( domain_port, src_id, im, ctl_info[ :ctld ], ctl_info[ :ctl_addr ] )
      when SOURCE_CLOSED then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed #{ src_id } #{ im.inspect } #{ addrinfo.ip_unpack.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_dst( dst )
      when SOURCE_CLOSED_READ then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed read #{ src_id } #{ im.inspect } #{ addrinfo.ip_unpack.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        set_dst_closing_write( dst )
      when SOURCE_CLOSED_WRITE then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed write #{ src_id } #{ im.inspect } #{ addrinfo.ip_unpack.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_read_dst( dst )
      end
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      return if data.empty?
      
      ctl_num = data[ 0 ].unpack( 'C' ).first
      # puts "debug infod got #{ ctl_num } #{ addrinfo.ip_unpack.inspect }"

      case ctl_num
      when TRAFF_INFOS then
        data2 = [ TRAFF_INFOS ].pack( 'C' )

        @traffs.sort.each do | im, info |
          data2 << [ [ im.bytesize ].pack( 'C' ), im, [ info[ :in ], info[ :out ] ].pack( 'Q>Q>' ) ].join
        end

        begin
          infod.sendmsg_nonblock( data2, 0, addrinfo )
        rescue Exception => e
          puts "#{ Time.new } infod sendmsg to #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } read dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      tun = dst_info[ :tun ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_tun_closing_write( tun )
        return
      end

      @traffs[ dst_info[ :im ] ][ :in ] += data.bytesize

      if tun && !tun.closed? then
        add_tun_wbuff( tun, pack_a_chunk( data ) )
      else
        # puts "debug add dst rbuff #{ data.bytesize }"
        add_dst_rbuff( dst, data )
      end
    end

    ##
    # read tund
    #
    def read_tund( tund )
      if tund.closed? then
        puts "#{ Time.new } read tund but tund closed?"
        return
      end

      tund_info = @tund_infos[ tund ]

      begin
        tun, _ = tund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } tund accept #{ e.class } #{ tund_info[ :im ].inspect }"
        close_dsts( tund_info[ :im ] )
        return
      end

      # puts "debug accept a tun"

      @tun_infos[ tun ] = {
        im: tund_info[ :im ],   # 标识
        dst: nil,               # 对应dst
        domain: nil,            # 目的地
        rbuff: '',              # 暂存不满一块的流量
        wbuff: '',              # 写前
        created_at: Time.new,   # 创建时间
        last_add_wbuff_at: nil, # 上一次加写前的时间
        closing: false,         # 准备关闭
        paused: false           # 是否暂停
      }

      add_read( tun, :tun )
    end

    ##
    # read tun
    #
    def read_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } read tun but tun closed?"
        return
      end

      tun_info = @tun_infos[ tun ]

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_read_tun( tun )
        return
      end

      # # debug
      # # let ping timeout
      # unless @debug_let_ping_timeout then
      #   sleep PING_TIMEOUT + 1
      #   @debug_let_ping_timeout = true
      #   return
      # end
      #
      # # debug
      # # let ping out of limit
      # sleep PING_TIMEOUT + 1

      dst = tun_info[ :dst ]

      unless dst then
        if data.bytesize < 2 then
          puts "#{ Time.new } tun ping less than 2?"
          close_tun( tun )
          return
        end

        dst_id = data[ 0, 8 ].unpack( 'Q>' ).first
        dst, dst_info = @dst_infos.find{ | _, info | info[ :dst_id ] == dst_id }

        unless dst then
          # puts "debug dst not found #{ dst_id }"
          close_tun( tun )
          return
        end

        tun_info[ :dst ] = dst
        tun_info[ :domain ] = dst_info[ :domain ]
        set_dst_info_tun( dst_info, tun )
        data = data[ 8..-1 ]

        if data.empty? then
          return
        end
      end

      data = "#{ tun_info[ :rbuff ] }#{ data }"

      loop do
        if data.bytesize <= 2 then
          tun_info[ :rbuff ] = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "#{ Time.new } zero traffic len?"
          close_tun( tun )
          close_dst( dst )
          return
        end

        chunk = data[ 2, len ]

        if chunk.bytesize < len then
          tun_info[ :rbuff ] = data
          break
        end

        chunk = @custom.decode( chunk )
        add_dst_wbuff( dst, chunk )
        data = data[ ( 2 + len )..-1 ]
      end
    end

    ##
    # write dst
    #
    def write_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } write dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
      tun = dst_info[ :tun ]
      data = dst_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if dst_info[ :closing_write ] then
          close_write_dst( dst )
        else
          @writes.delete( dst )
        end

        return
      end

      # 写入
      begin
        written = dst.write_nonblock( data )
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_write_dst( dst )
        close_read_tun( tun )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @traffs[ dst_info[ :im ] ][ :out ] += written

      if tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ].inspect }"
          add_read( tun )
          tun_info[ :paused ] = false
        end
      end
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write tun but tun closed?"
        return
      end

      tun_info = @tun_infos[ tun ]
      dst = tun_info[ :dst ]
      data = tun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if tun_info[ :closing_write ] then
          close_write_tun( tun )
        else
          @writes.delete( tun )
        end

        return
      end

      # 写入
      begin
        written = tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tun #{ e.class }"
        close_tun( tun )
        close_read_dst( dst )
        return
      end

      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data
      @traffs[ tun_info[ :im ] ][ :out ] += written

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
          add_read( dst )
          dst_info[ :paused ] = false
        end
      end
    end

  end
end
