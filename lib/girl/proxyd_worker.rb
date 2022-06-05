module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, nameserver )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @roles = {}                     # sock => :dotr / :tcpd / :tcp / :infod / :dst / :tund / :tun / :dns
      @tcp_infos = {}                 # tcp => { :rbuff, :wbuff, :im, :created_at, :last_recv_at, :closing }
      @tund_infos = {}                # tund => { :im }
      @resolv_caches = {}             # domain => [ ip, created_at ]
      @dst_infos = ConcurrentHash.new # dst => { :dst_id, :im, :domain, :rbuff, :tun, :wbuff, :src_id,
                                      #          :created_at, :connected, :last_add_wbuff_at, :closing_write, :closing, :paused }
      @tun_infos = ConcurrentHash.new # tun => { :im, :dst, :domain, :rbuff, :wbuff, :created_at, :last_add_wbuff_at, :closing, :paused }
      @dns_infos = {}                 # dns => { :im, :src_id, :domain, :port, :tcp, :closing }
      @im_infos = ConcurrentHash.new  # im => { :in, :out, :tund_ports }
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )

      new_a_pipe
      new_tcpds( proxyd_port )
      new_a_infod( proxyd_port )
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
          when :tcpd then
            read_tcpd( sock )
          when :tcp then
            read_tcp( sock )
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
          when :tcp then
            write_tcp( sock )
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
    # add tcp wbuff
    #
    def add_tcp_wbuff( tcp, data )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :wbuff ] << data
      add_write( tcp )
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
      return unless im
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
    # close tcp
    #
    def close_tcp( tcp )
      return if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      tcp_info = @tcp_infos.delete( tcp )
      close_dsts( tcp_info[ :im ] )
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

          @tcp_infos.select{ | tcp, info | !tcp.closed? && ( now - ( info[ :last_recv_at ] || info[ :created_at ] ) >= EXPIRE_AFTER ) }.values.each do | tcp_info |
            puts "#{ Time.new } expire tcp #{ tcp_info[ :im ].inspect }"
            tcp_info[ :closing ] = true
            next_tick
          end

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
              @im_infos.each{ | _, info | info[ :in ] = info[ :out ] = 0 }
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( ipaddr, domain, port, src_id, tcp )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      im = tcp_info[ :im ]

      begin
        dst = Socket.new( ipaddr.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ e.class } #{ im } #{ domain.inspect } #{ port }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      ip = ipaddr.to_s
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect destination #{ e.class } #{ im } #{ domain.inspect } #{ ip } #{ port }"
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
      # puts "debug add paired #{ im.inspect } #{ src_id } #{ dst_id } #{ domain }:#{ port }"
      add_tcp_wbuff( tcp, pack_a_chunk( data ) )

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
    def new_a_infod( proxyd_port )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( Socket.sockaddr_in( proxyd_port, '127.0.0.1' ) )
      puts "#{ Time.new } infod bind on #{ proxyd_port }"
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
    def new_a_tund( im )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund.listen( 127 )
      @tund_infos[ tund ] = { im: im }
      add_read( tund, :tund )
      tund.local_address.ip_port
    end

    ##
    # new tcpds
    #
    def new_tcpds( begin_port )
      10.times do | i |
        tcpd_port = begin_port + i
        tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
        tcpd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
        tcpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        tcpd.bind( Socket.sockaddr_in( tcpd_port, '0.0.0.0' ) )
        tcpd.listen( 127 )
        puts "#{ Time.new } tcpd listen on #{ tcpd_port }"
        add_read( tcpd, :tcpd )
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
      @tcp_infos.select{ | _, info | info[ :closing ] }.keys.each{ | tcp | close_tcp( tcp ) }
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
        port = dns_info[ :port ]
        src_id = dns_info[ :src_id ]
        tcp = dns_info[ :tcp ]
        new_a_dst( ipaddr, domain, port, src_id, tcp )
      end

      close_dns( dns )
    end

    ##
    # read tcpd
    #
    def read_tcpd( tcpd )
      if tcpd.closed? then
        puts "#{ Time.new } read tcpd but tcpd closed?"
        return
      end

      begin
        tcp, _ = tcpd.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } tcpd accept #{ e.class }"
        return
      end

      @tcp_infos[ tcp ] = {
        rbuff: '',            # 暂存不满一块的流量
        wbuff: '',            # 写前
        im: nil,              # 标识
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到控制流量时间
        closing: false        # 准备关闭
      }

      # puts "debug accept a tcp"
      add_read( tcp, :tcp )
    end

    ##
    # read tcp
    #
    def read_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } read tcp but tcp closed?"
        return
      end

      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = "#{ tcp_info[ :rbuff ] }#{ data }"

      loop do
        if data.bytesize <= 2 then
          tcp_info[ :rbuff ] = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "#{ Time.new } read tcp zero traffic len?"
          close_tcp( tcp )
          return
        end

        chunk = data[ 2, len ]

        if chunk.bytesize < len then
          tcp_info[ :rbuff ] = data
          break
        end

        data2 = @custom.decode( chunk )
        deal_ctlmsg( data2, tcp )
        data = data[ ( 2 + len )..-1 ]
      end
    end

    ##
    # deal ctlmsg
    #
    def deal_ctlmsg( data, tcp )
      return if data.nil? || data.empty? || tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :last_recv_at ] = Time.new
      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when HELLO then
        return if tcp_info[ :im ] || data.bytesize <= 1
        im = data[ 1..-1 ]
        result = @custom.check( im )

        if result != :success then
          puts "#{ Time.new } #{ result } #{ im.inspect }"
          return
        end

        tcp_info[ :im ] = im
        im_info = @im_infos[ im ]

        unless im_info then
          tund_ports = []

          10.times do
            tund_ports << new_a_tund( im )
          end

          im_info = {
            in: 0,
            out: 0,
            tund_ports: tund_ports
          }

          @im_infos[ im ] = im_info
        end

        puts "#{ Time.new } got hello #{ im.inspect }"
        print "ims #{ @im_infos.size } tcps #{ @tcp_infos.size } tunds #{ @tund_infos.size }"
        puts " dsts #{ @dst_infos.size } tuns #{ @tun_infos.size } dnses #{ @dns_infos.size }"

        puts "#{ Time.new } add tcp wbuff tund ports #{ im_info[ :tund_ports ].inspect }"
        data2 = [ TUND_PORTS, *im_info[ :tund_ports ] ].pack( 'Cn*' )
        add_tcp_wbuff( tcp, pack_a_chunk( data2 ) )
      when A_NEW_SOURCE then
        return if tcp_info[ :im ].nil? || data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        domain_port = data[ 9..-1 ]
        dst_info = @dst_infos.values.find{ | info | info[ :src_id ] == src_id }

        if dst_info then
          puts "#{ Time.new } dst info already exist, ignore a new source #{ src_id } #{ domain_port }"
          return
        end

        # puts "debug got a new source #{ tcp_info[ :im ].inspect } #{ src_id } #{ domain_port.inspect }"
        resolve_domain_port( domain_port, src_id, tcp )
      when SOURCE_CLOSED then
        return if tcp_info[ :im ].nil? || data.bytesize != 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        # puts "debug got src closed #{ tcp_info[ :im ].inspect } #{ src_id }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_dst( dst )
      when SOURCE_CLOSED_READ then
        return if tcp_info[ :im ].nil? || data.bytesize != 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        # puts "debug got src closed read #{ tcp_info[ :im ].inspect } #{ src_id }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        set_dst_closing_write( dst )
      when SOURCE_CLOSED_WRITE then
        return if tcp_info[ :im ].nil? || data.bytesize != 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        # puts "debug got src closed write #{ tcp_info[ :im ].inspect } #{ src_id }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_read_dst( dst )
      end
    end

    ##
    # resolve domain port
    #
    def resolve_domain_port( domain_port, src_id, tcp )
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ipaddr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain.inspect } hit resolv cache #{ ipaddr.to_s }"
          new_a_dst( ipaddr, domain, port, src_id, tcp )
          return
        end

        # puts "debug expire #{ domain.inspect } resolv cache"
        @resolv_caches.delete( domain )
      end

      begin
        ipaddr = IPAddr.new( domain )

        if ipaddr.ipv4? || ipaddr.ipv6? then
          new_a_dst( ipaddr, domain, port, src_id, tcp )
          return
        end
      rescue Exception => e
      end

      begin
        packet = Net::DNS::Packet.new( domain )
      rescue Exception => e
        puts "#{ Time.new } new packet #{ e.class } #{ domain.inspect }"
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain.inspect }"
        dns.sendmsg_nonblock( packet.data, 0, @nameserver_addr )
      rescue Exception => e
        puts "#{ Time.new } dns sendmsg #{ e.class } #{ domain.inspect }"
        dns.close
        return
      end

      dns_info = {
        src_id: src_id,
        domain: domain,
        port: port,
        tcp: tcp,
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
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      return if data.empty?

      im_infos = []

      @im_infos.sort.map do | im, _info |
        im_infos << {
          im: im,
          in: _info[ :in ],
          out: _info[ :out ]
        }
      end

      report = {
        sizes: {
          im_infos: @im_infos.size,
          tcp_infos: @tcp_infos.size,
          tund_infos: @tund_infos.size,
          dst_infos: @dst_infos.size,
          tun_infos: @tun_infos.size,
          dns_infos: @dns_infos.size,
          resolv_caches: @resolv_caches.size
        },
        im_infos: im_infos
      }

      begin
        infod.sendmsg_nonblock( JSON.generate( report ), 0, addrinfo )
      rescue Exception => e
        puts "#{ Time.new } infod sendmsg to #{ e.class } #{ addrinfo.ip_unpack.inspect }"
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

      @im_infos[ dst_info[ :im ] ][ :in ] += data.bytesize

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
          puts "#{ Time.new } read tun zero traffic len?"
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
    # write tcp
    #
    def write_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } write tcp but tcp closed?"
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = tcp_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        @writes.delete( tcp )
        return
      end

      # 写入
      begin
        written = tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
      @im_infos[ tcp_info[ :im ] ][ :out ] += written
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
      @im_infos[ dst_info[ :im ] ][ :out ] += written

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
      @im_infos[ tun_info[ :im ] ][ :out ] += written

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
