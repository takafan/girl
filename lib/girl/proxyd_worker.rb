module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port, nameserver )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @deleting_ctl_infos = []
      @closing_dsts = []
      @closing_dnses = []
      @paused_dsts = []
      @paused_atuns = []
      @resume_dsts = []
      @resume_atuns = []
      @roles = {}         # sock => :dotr / :ctld / :ctl / :infod / :dst / :atund / :btund / :atun / :btun / :dns
      @ctl_infos = {}     # ctl => {}
      @dst_infos = {}     # dst => {}
      @atund_infos = {}   # atund => {}
      @btund_infos = {}   # btund => {}
      @atun_infos = {}    # atun => {}
      @btun_infos = {}    # btun => {}
      @dns_infos = {}     # dns => {}
      @resolv_caches = {} # domain => [ ip, created_at ]
      @traff_ins = {}     # im => 0
      @traff_outs = {}    # im => 0
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @mutex = Mutex.new

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_ctlds( proxyd_port )
      new_a_infod( infod_port )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire
      loop_check_resume
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          case @roles[ sock ]
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
          when :atund then
            read_atund( sock )
          when :btund then
            read_btund( sock )
          when :atun then
            read_atun( sock )
          when :btun then
            read_btun( sock )
          else
            puts "p#{ Process.pid } #{ Time.new } read unknown role"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :dst then
            write_dst( sock )
          when :btun then
            write_btun( sock )
          else
            puts "p#{ Process.pid } #{ Time.new } write unknown role"
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
    # add closing dns
    #
    def add_closing_dns( dns )
      return if dns.closed? || @closing_dnses.include?( dns )
      @closing_dnses << dns
      next_tick
    end

    ##
    # add closing dst
    #
    def add_closing_dst( dst )
      return if dst.closed? || @closing_dsts.include?( dst )
      @closing_dsts << dst
      next_tick
    end

    ##
    # add btun wbuff
    #
    def add_btun_wbuff( btun, data )
      return if btun.closed?
      btun_info = @btun_infos[ btun ]
      btun_info[ :wbuff ] << data
      add_write( btun )

      if btun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause dst #{ btun_info[ :domain ] }"
        add_paused_dst( btun_info[ :dst ] )
      end
    end

    ##
    # add dst rbuff
    #
    def add_dst_rbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :rbuff ] << data

      if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug dst.rbuff full"
        close_dst( dst )
      end
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.closed? || @closing_dsts.include?( dst )
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      dst_info[ :last_recv_at ] = Time.new
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause atun #{ dst_info[ :domain ] }"
        add_paused_atun( dst_info[ :atun ] )
      end
    end

    ##
    # add paused atun
    #
    def add_paused_atun( atun )
      return if tun.closed? || @paused_atuns.include?( atun )
      @reads.delete( atun )
      @paused_atuns << atun
    end

    ##
    # add paused dst
    #
    def add_paused_dst( dst )
      return if dst.closed? || @paused_dsts.include?( dst )
      @reads.delete( dst )
      @paused_dsts << dst
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end

      next_tick
    end

    ##
    # add resume atun
    #
    def add_resume_atun( atun )
      return if @resume_atuns.include?( atun )
      @resume_atuns << atun
      next_tick
    end

    ##
    # add resume dst
    #
    def add_resume_dst( dst )
      return if @resume_dsts.include?( dst )
      @resume_dsts << dst
      next_tick
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.closed? || @writes.include?( sock )
      @writes << sock
      next_tick
    end

    ##
    # close atun
    #
    def close_atun( atun )
      return if atun.closed?
      # puts "debug close atun"
      close_sock( atun )
      del_atun_info( atun )
    end

    ##
    # close atund
    #
    def close_atund( atund )
      return if atund.closed?
      # puts "debug close atund"
      close_sock( atund )
      @atund_infos.delete( atund )
    end

    ##
    # close btun
    #
    def close_btun( btun )
      return if btun.closed?
      # puts "debug close btun"
      close_sock( btun )
      btun_info = @btun_infos.delete( btun )
      dst = btun_info[ :dst ]

      if dst then
        @paused_dsts.delete( dst )
      end
    end

    ##
    # close btund
    #
    def close_btund( btund )
      return if btund.closed?
      # puts "debug close btund"
      close_sock( btund )
      @btund_infos.delete( btund )
    end

    ##
    # close dns
    #
    def close_dns( dns )
      close_sock( dns )
      @dns_infos.delete( dns )
    end

    ##
    # close dst
    #
    def close_dst( dst )
      return if dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      dst_info = del_dst_info( dst )
      atun = dst_info[ :atun ]
      btun = dst_info[ :btun ]

      if atun then
        close_sock( atun )
        del_atun_info( atun )
      end

      if btun then
        close_sock( btun )
        @btun_infos.delete( btun )
      end
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.closed?
      # puts "debug close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        @writes.delete( dst )
        @roles.delete( dst )
        del_dst_info( dst )
      end
    end

    ##
    # close sock
    #
    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.closed?
      # puts "debug close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        @reads.delete( dst )
        @roles.delete( dst )
        dst_info = del_dst_info( dst )
      end
    end

    ##
    # deal with destination ipaddr
    #
    def deal_with_destination_ipaddr( ipaddr, ctl_addr, src_id, domain, port )
      ctl_info = @ctl_infos[ ctl_addr ]

      unless ctl_info then
        puts "p#{ Process.pid } #{ Time.new } ctl info not found #{ Addrinfo.new( ctl_addr ).inspect }"
        return
      end

      begin
        dst = Socket.new( ipaddr.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } new a dst #{ domain } #{ port } #{ e.class }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      ip = ipaddr.to_s
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ domain } #{ ip } #{ port } #{ e.class }"
        dst.close
        return
      end

      dst_id = dst.local_address.ip_port

      @dst_infos[ dst ] = {
        id: dst_id,           # id
        ctl_addr: ctl_addr,   # 对应ctl
        im: ctl_info[ :im ],  # 标识
        domain: domain,       # 目的地
        connected: false,     # 是否已连接
        rbuff: '',            # 对应的tun没准备好，暂存读到的流量
        atun: nil,            # 对应的atun
        btun: nil,            # 对应的btun
        wbuff: '',            # 从tun读到的流量
        src_id: src_id,       # 近端src id
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到新流量（由tun收到）的时间
        last_sent_at: nil,    # 上一次发出流量（由tun发出）的时间
        closing_write: false  # 准备关闭写
      }

      add_read( dst, :dst )
      add_write( dst )

      ctl_info[ :dst_ids ][ src_id ] = dst_id
      ctl_info[ :dsts ][ dst_id ] = dst

      data = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
      # puts "debug add ctlmsg paired #{ src_id } #{ dst_id }"
      send_ctlmsg( ctl_info[ :ctld ], data, ctl_addr )
    end

    ##
    # del atun info
    #
    def del_atun_info( atun )
      @atun_infos.delete( atun )
      @paused_atuns.delete( atun )
      @resume_atuns.delete( atun )
    end

    ##
    # del ctl info
    #
    def del_ctl_info( ctl_addr )
      # puts "debug delete ctl info"
      ctl_info = @ctl_infos.delete( ctl_addr )
      close_atund( ctl_info[ :atund ] )
      close_btund( ctl_info[ :btund ] )
    end

    ##
    # del dst info
    #
    def del_dst_info( dst )
      # puts "debug delete dst info"
      dst_info = @dst_infos.delete( dst )
      @paused_dsts.delete( dst )
      @resume_dsts.delete( dst )
      ctl_addr = dst_info[ :ctl_addr ]
      ctl_info = @ctl_infos[ ctl_addr ]

      if ctl_info then
        ctl_info[ :dsts ].delete( dst_info[ :id ] )
        ctl_info[ :dst_ids ].delete( dst_info[ :src_id ] )
      end

      dst_info
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            now = Time.new

            @ctl_infos.keys.each do | ctl_addr |
              ctl_info = @ctl_infos[ ctl_addr ]

              if now - ctl_info[ :last_recv_at ] >= EXPIRE_CTL
                puts "p#{ Process.pid } #{ Time.new } expire ctl #{ EXPIRE_CTL } #{ ctl_info[ :addrinfo ].inspect } tund ports #{ ctl_info[ :atund_port ] } #{ ctl_info[ :btund_port ] }"

                unless @deleting_ctl_infos.include?( ctl_addr ) then
                  @deleting_ctl_infos << ctl_addr
                  next_tick
                end
              end
            end

            @dst_infos.keys.each do | dst |
              dst_info = @dst_infos[ dst ]

              if dst_info[ :connected ] then
                last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
                last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]
                expire_after = EXPIRE_AFTER
                is_expire = ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after )
              else
                expire_after = EXPIRE_CONNECTING
                is_expire = ( now - dst_info[ :created_at ] >= expire_after )
              end

              if is_expire then
                puts "p#{ Process.pid } #{ Time.new } expire dst #{ expire_after } #{ dst_info[ :domain ] }"
                add_closing_dst( dst )
              end
            end

            @dns_infos.keys.each do | dns |
              dns_info = @dns_infos[ dns ]

              if now - dns_info[ :created_at ] >= EXPIRE_NEW then
                 puts "p#{ Process.pid } #{ Time.new } expire dns #{ EXPIRE_NEW } #{ dns_info[ :domain ] }"
                 add_closing_dns( dns )
              end
            end
          end
        end
      end
    end

    ##
    # loop check resume
    #
    def loop_check_resume
      Thread.new do
        loop do
          sleep CHECK_RESUME_INTERVAL

          @mutex.synchronize do
            @paused_dsts.each do | dst |
              dst_info = @dst_infos[ dst ]
              btun = dst_info[ :btun ]

              if btun && !btun.closed? then
                btun_info = @btun_infos[ btun ]

                if btun_info[ :wbuff ].bytesize < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain ] }"
                  add_resume_dst( dst )
                end
              end
            end

            @paused_atuns.each do | atun |
              atun_info = @atun_infos[ atun ]
              dst = atun_info[ :dst ]

              if dst && !dst.closed? then
                dst_info = @dst_infos[ dst ]

                if dst_info[ :wbuff ].bytesize < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } resume atun #{ atun_info[ :domain ] }"
                  add_resume_atun( atun )
                end
              end
            end
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

            @mutex.synchronize do
              if Time.new.day == RESET_TRAFF_DAY then
                puts "p#{ Process.pid } #{ Time.new } reset traffs"
                @traff_ins.transform_values!{ | _ | 0 }
                @traff_outs.transform_values!{ | _ | 0 }
              end
            end
          end
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
      puts "p#{ Process.pid } #{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
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
    def new_ctlds( proxyd_port )
      10.times do | i |
        ctld_port = proxyd_port + i
        ctld = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        ctld.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        ctld.bind( Socket.sockaddr_in( ctld_port, '0.0.0.0' ) )
        puts "p#{ Process.pid } #{ Time.new } ctld bind on #{ ctld_port }"
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
    def resolve_domain_port( domain_port, ctl_addr, src_id )
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ipaddr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain } hit resolv cache #{ ipaddr.to_s }"
          deal_with_destination_ipaddr( ipaddr, ctl_addr, src_id, domain, port )
          return
        end

        # puts "debug expire #{ domain } resolv cache"
        @resolv_caches.delete( domain )
      end

      begin
        ipaddr = IPAddr.new( domain )

        if ipaddr.ipv4? || ipaddr.ipv6? then
          deal_with_destination_ipaddr( ipaddr, ctl_addr, src_id, domain, port )
          return
        end
      rescue Exception => e
      end

      begin
        packet = Net::DNS::Packet.new( domain )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } new packet #{ e.class } #{ domain.inspect }"
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain }"
        dns.sendmsg_nonblock( packet.data, 0, @nameserver_addr )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dns sendmsg #{ e.class }"
        dns.close
        return
      end

      add_read( dns, :dns )
      @dns_infos[ dns ] = {
        ctl_addr: ctl_addr,
        src_id: src_id,
        domain: domain,
        port: port,
        created_at: Time.new
      }
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( ctld, data, to_addr )
      data = @custom.encode( data )

      begin
        ctld.sendmsg_nonblock( data, 0, to_addr )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } ctld sendmsg #{ e.class }"
      end
    end

    ##
    # set btun closing
    #
    def set_btun_closing( btun )
      return if btun.closed?
      btun_info = @btun_infos[ btun ]
      return if btun_info[ :closing ]
      # puts "debug set btun closing"
      btun_info[ :closing ] = true
      add_write( btun )
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed? || @closing_dsts.include?( dst )
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      # puts "debug set dst closing write"
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )

      if @deleting_ctl_infos.any? then
        @deleting_ctl_infos.each{ | ctl_addr | del_ctl_info( ctl_addr ) }
        @deleting_ctl_infos.clear
      end

      if @closing_dsts.any? then
        @closing_dsts.each{ | dst | close_dst( dst ) }
        @closing_dsts.clear
      end

      if @closing_dnses.any? then
        @closing_dnses.each{ | dns | close_dns( dns ) }
        @closing_dnses.clear
      end

      if @resume_dsts.any? then
        @resume_dsts.each do | dst |
          add_read( dst )
          @paused_dsts.delete( dst )
        end

        @resume_dsts.clear
      end

      if @resume_atuns.any? then
        @resume_atuns.each do | atun |
          add_read( atun )
          @paused_atuns.delete( atun )
        end

        @resume_atuns.clear
      end
    end

    ##
    # read dns
    #
    def read_dns( dns )
      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      # puts "debug recv dns #{ data.inspect }"
      begin
        packet = Net::DNS::Packet::parse( data )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } parse packet #{ e.class }"
        close_dns( dns )
        return
      end

      ans = packet.answer.find{ | ans | ans.class == Net::DNS::RR::A }

      if ans then
        dns_info = @dns_infos[ dns ]
        domain = dns_info[ :domain ]
        ipaddr = IPAddr.new( ans.value )
        @resolv_caches[ domain ] = [ ipaddr, Time.new ]
        ctl_addr = dns_info[ :ctl_addr ]
        src_id = dns_info[ :src_id ]
        port = dns_info[ :port ]
        deal_with_destination_ipaddr( ipaddr, ctl_addr, src_id, domain, port )
      end

      close_dns( dns )
    end

    ##
    # read ctld
    #
    def read_ctld( ctld )
      data, addrinfo, rflags, *controls = ctld.recvmsg
      data = @custom.decode( data )
      ctl_num = data[ 0 ].unpack( 'C' ).first
      ctl_addr = addrinfo.to_sockaddr
      ctl_info = @ctl_infos[ ctl_addr ]

      case ctl_num
      when HELLO then
        if ctl_info then
          atund_port, btund_port = ctl_info[ :atund_port ], ctl_info[ :btund_port ]
        else
          return if data.bytesize <= 1
          im = data[ 1..-1 ]
          result = @custom.check( im, addrinfo )

          if result != :success then
            puts "p#{ Process.pid } #{ Time.new } #{ result }"
            return
          end

          unless @traff_ins.include?( im ) then
            @traff_ins[ im ] = 0
            @traff_outs[ im ] = 0
          end

          atund = new_a_tund
          atund_port = atund.local_address.ip_port
          btund = new_a_tund
          btund_port = btund.local_address.ip_port
          add_read( atund, :atund )
          add_read( btund, :btund )

          @atund_infos[ atund ] = {
            ctl_addr: ctl_addr,
            im: im
          }

          @btund_infos[ btund ] = {
            ctl_addr: ctl_addr,
            im: im
          }

          @ctl_infos[ ctl_addr ] = {
            ctld: ctld,             # 对应的ctld
            addrinfo: addrinfo,     # 地址
            im: im,                 # 标识
            atund: atund,           # 对应atund，src->dst
            atund_port: atund_port, # atund端口
            btund: btund,           # 对应btund，dst->src
            btund_port: btund_port, # btund端口
            dsts: {},               # dst_id => dst
            dst_ids: {},            # src_id => dst_id
            last_recv_at: Time.new  # 上一次收到流量的时间
          }

          puts "p#{ Process.pid } #{ Time.new } got hello #{ im.inspect }, atund listen on #{ atund_port }, btund listen on #{ btund_port }, ctl infos size #{ @ctl_infos.size }"
        end

        data2 = [ TUND_PORT, atund_port, btund_port ].pack( 'Cnn' )
        send_ctlmsg( ctld, data2, ctl_addr )
      when A_NEW_SOURCE then
        unless ctl_info then
          send_ctlmsg( ctld, [ UNKNOWN_CTL_ADDR ].pack( 'C' ), addrinfo )
          return
        end

        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        dst_id = ctl_info[ :dst_ids ][ src_id ]

        if dst_id then
          data2 = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
          # puts "debug dst id exist, send ctlmsg paired #{ src_id } #{ dst_id }"
          send_ctlmsg( ctld, data2, ctl_addr )
          return
        end

        domain_port = data[ 9..-1 ]
        # puts "debug got a new source #{ src_id } #{ domain_port }"
        resolve_domain_port( domain_port, ctl_addr, src_id )
        ctl_info[ :last_recv_at ] = Time.new
      when CTL_FIN then
        return unless ctl_info
        # puts "debug got ctl fin #{ addrinfo.inspect }"
        del_ctl_info( ctl_addr )
      end
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first
      # puts "debug infod got #{ ctl_num } #{ addrinfo.ip_unpack.inspect }"

      case ctl_num
      when TRAFF_INFOS then
        data2 = [ TRAFF_INFOS ].pack( 'C' )

        @traff_ins.keys.sort.each do | im |
          traff_in = @traff_ins[ im ]
          traff_out = @traff_outs[ im ]
          data2 << [ [ im.bytesize ].pack( 'C' ), im, [ traff_in, traff_out ].pack( 'Q>Q>' ) ].join
        end

        begin
          infod.sendmsg_nonblock( data2, 0, addrinfo )
        rescue Exception => e
          puts "p#{ Process.pid } #{ Time.new } infod sendmsg to #{ addrinfo.ip_unpack.inspect } #{ e.class }"
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
      if dst.closed? then
        puts "p#{ Process.pid } #{ Time.new } read dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      btun = dst_info[ :btun ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue IO::WaitReadable
        print 'r'
        return
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )

        if btun then
          set_btun_closing( btun )
        end

        return
      end

      @traff_ins[ dst_info[ :im ] ] += data.bytesize
      # puts "debug read dst #{ data.bytesize }"

      if btun then
        add_btun_wbuff( btun, pack_a_chunk( data ) )
      else
        # puts "debug add dst.rbuff #{ data.bytesize }"
        add_dst_rbuff( dst, data )
      end
    end

    ##
    # read atund
    #
    def read_atund( atund )
      if atund.closed? then
        puts "p#{ Process.pid } #{ Time.new } read atund but atund closed?"
        return
      end

      atund_info = @atund_infos[ atund ]

      begin
        atun, _ = atund.accept_nonblock
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } atund #{ atund_info[ :im ] } accept #{ e.class }"
        puts e.full_message
        return
      end

      # puts "debug accept a atun #{ atund_info[ :im ] }"

      @atun_infos[ atun ] = {
        ctl_addr: atund_info[ :ctl_addr ], # 对应ctl
        im: atund_info[ :im ],             # 标识
        dst: nil,                          # 对应dst
        domain: nil,                       # 目的地
        rbuff: '',                         # 暂存当前块没收全的流量
        wait_bytes: 0,                     # 还差多少字节收全当前块
        lbuff: ''                          # 流量截断在长度前缀处
      }

      add_read( atun, :atun )
    end

    ##
    # read btund
    #
    def read_btund( btund )
      if btund.closed? then
        puts "p#{ Process.pid } #{ Time.new } read btund but btund closed?"
        return
      end

      btund_info = @btund_infos[ btund ]

      begin
        btun, _ = btund.accept_nonblock
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } btund #{ btund_info[ :im ] } accept #{ e.class }"
        puts e.full_message
        return
      end

      # puts "debug accept a btun #{ btund_info[ :im ] }"

      @btun_infos[ btun ] = {
        ctl_addr: btund_info[ :ctl_addr ], # 对应ctl
        im: btund_info[ :im ],             # 标识
        dst: nil,                          # 对应dst
        domain: nil,                       # 目的地
        wbuff: '',                         # 写前
        closing: false                     # 准备关闭
      }

      add_read( btun, :btun )
    end

    ##
    # read atun
    #
    def read_atun( atun )
      if atun.closed? then
        puts "p#{ Process.pid } #{ Time.new } read atun but atun closed?"
        return
      end

      atun_info = @atun_infos[ atun ]
      dst = atun_info[ :dst ]

      begin
        data = atun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read atun #{ atun_info[ :im ] } #{ e.class }"
        close_atun( atun )

        if dst then
          set_dst_closing_write( dst )
        end

        return
      end

      unless dst then
        if data.bytesize < 2 then
          # puts "debug unexpect data length #{ data.bytesize }"
          close_atun( atun )
        end

        dst_id = data[ 0, 2 ].unpack( 'n' ).first
        ctl_addr = atun_info[ :ctl_addr ]
        ctl_info = @ctl_infos[ ctl_addr ]

        unless ctl_info then
          close_atun( atun )
          return
        end

        dst = ctl_info[ :dsts ][ dst_id ]

        unless dst then
          close_atun( atun )
          return
        end

        # puts "debug set atun.dst #{ dst_id }"
        atun_info[ :dst ] = dst
        dst_info = @dst_infos[ dst ]
        atun_info[ :domain ] = dst_info[ :domain ]
        dst_info[ :atun ] = atun

        data = data[ 2..-1 ]
      end

      until data.empty? do
        wait_bytes = atun_info[ :wait_bytes ]

        if wait_bytes > 0 then
          len = wait_bytes
          # puts "debug wait bytes #{ len }"
        else
          lbuff = atun_info[ :lbuff ]

          if lbuff.empty? then
            # 长度缓存为空，从读到的流量里取长度
            # 两个字节以下，记进长度缓存
            if data.bytesize <= 2 then
              # puts "debug set atun.lbuff #{ data.inspect }"
              atun_info[ :lbuff ] = data
              return
            end

            len = data[ 0, 2 ].unpack( 'n' ).first
            data = data[ 2..-1 ]
          elsif lbuff.bytesize == 1 then
            # 长度缓存记有一个字节，补一个字节
            lbuff = "#{ lbuff }#{ data[ 0 ] }"

            if data.bytesize == 1 then
              # puts "debug add atun.lbuff a byte #{ data.inspect }"
              atun_info[ :lbuff ] = lbuff
              return
            end

            # 使用长度缓存
            len = lbuff.unpack( 'n' ).first
            atun_info[ :lbuff ].clear
            data = data[ 1..-1 ]
          else
            # 使用长度缓存
            len = lbuff.unpack( 'n' ).first
            atun_info[ :lbuff ].clear
          end
        end

        chunk = data[ 0, len ]
        chunk_size = chunk.bytesize

        if chunk_size == len then
          # 取完整了
          chunk = @custom.decode( "#{ atun_info[ :rbuff ] }#{ chunk }" )
          # puts "debug decode and add dst.wbuff #{ chunk.bytesize }"
          add_dst_wbuff( dst, chunk )
          atun_info[ :rbuff ].clear
          atun_info[ :wait_bytes ] = 0
        else
          # 暂存
          # puts "debug add atun.rbuff #{ chunk_size } wait bytes #{ len - chunk_size }"
          atun_info[ :rbuff ] << chunk
          atun_info[ :wait_bytes ] = len - chunk_size
        end

        data = data[ chunk_size..-1 ]
      end
    end

    ##
    # read btun
    #
    def read_btun( btun )
      if btun.closed? then
        puts "p#{ Process.pid } #{ Time.new } read btun but btun closed?"
        return
      end

      btun_info = @btun_infos[ btun ]

      begin
        data = btun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read btun #{ btun_info[ :im ] } #{ e.class }"
        close_btun( btun )
        return
      end

      if data.bytesize != 2 then
        close_btun( btun )
        return
      end

      # puts "debug read btun #{ data.inspect }"
      @traff_ins[ btun_info[ :im ] ] += data.bytesize
      dst = btun_info[ :dst ]

      if dst then
        # puts "debug unexpect data"
        close_btun( btun )
        return
      end

      dst_id = data.unpack( 'n' ).first
      ctl_addr = btun_info[ :ctl_addr ]
      ctl_info = @ctl_infos[ ctl_addr ]

      unless ctl_info then
        # puts "debug ctl info not found"
        close_btun( btun )
        return
      end

      dst = ctl_info[ :dsts ][ dst_id ]

      unless dst then
        # puts "debug dst #{ dst_id } not found"
        close_btun( btun )
        return
      end

      # puts "debug set btun.dst #{ dst_id }"
      btun_info[ :dst ] = dst
      dst_info = @dst_infos[ dst ]
      btun_info[ :domain ] = dst_info[ :domain ]

      unless dst_info[ :rbuff ].empty? then
        data2 = ''

        until dst_info[ :rbuff ].empty? do
          _data = dst_info[ :rbuff ][ 0, CHUNK_SIZE ]
          data_size = _data.bytesize
          # puts "debug move dst.rbuff to btun.wbuff"
          data2 << pack_a_chunk( _data )
          dst_info[ :rbuff ] = dst_info[ :rbuff ][ data_size..-1 ]
        end

        add_btun_wbuff( btun, data2 )
      end

      dst_info[ :btun ] = btun
    end

    ##
    # write dst
    #
    def write_dst( dst )
      if dst.closed? then
        puts "p#{ Process.pid } #{ Time.new } write dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
      atun = dst_info[ :atun ]
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
      rescue IO::WaitWritable
        print 'w'
        return
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_write_dst( dst )

        if atun then
          close_atun( atun )
        end

        return
      end

      # puts "debug write dst #{ written }"
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @traff_outs[ dst_info[ :im ] ] += written
    end

    ##
    # write btun
    #
    def write_btun( btun )
      if btun.closed? then
        puts "p#{ Process.pid } #{ Time.new } write btun but btun closed?"
        return
      end

      btun_info = @btun_infos[ btun ]
      dst = btun_info[ :dst ]
      data = btun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if btun_info[ :closing ] then
          close_btun( btun )
        else
          @writes.delete( btun )
        end

        return
      end

      # 写入
      begin
        written = btun.write_nonblock( data )
      rescue IO::WaitWritable
        print 'w'
        return
      rescue Exception => e
        # puts "debug write btun #{ e.class }"
        close_btun( btun )
        close_read_dst( dst ) if dst
        return
      end

      # puts "debug write btun #{ written }"
      data = data[ written..-1 ]
      btun_info[ :wbuff ] = data
      @traff_outs[ btun_info[ :im ] ] += written

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]
        dst_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
