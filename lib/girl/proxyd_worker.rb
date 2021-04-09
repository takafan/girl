module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @deleting_ctl_infos = []
      @closing_dsts = []
      @paused_dsts = []
      @paused_atuns = []
      @resume_dsts = []
      @resume_atuns = []
      @roles = ConcurrentHash.new         # sock => :dotr / :ctld / :ctl / :infod / :dst / :atund / :btund / :atun / :btun
      @ctl_infos = ConcurrentHash.new     # ctl => {}
      @dst_infos = ConcurrentHash.new     # dst => {}
      @atund_infos = ConcurrentHash.new   # atund => {}
      @btund_infos = ConcurrentHash.new   # btund => {}
      @atun_infos = ConcurrentHash.new    # atun => {}
      @btun_infos = ConcurrentHash.new    # btun => {}
      @resolv_caches = ConcurrentHash.new # domain => [ ip, created_at ]
      @traff_ins = ConcurrentHash.new     # im => 0
      @traff_outs = ConcurrentHash.new    # im => 0

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_ctld( proxyd_port )
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
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :dst then
            write_dst( sock )
          when :btun then
            write_btun( sock )
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
    # add btun wbuff
    #
    def add_btun_wbuff( btun, data )
      return if btun.closed?
      btun_info = @btun_infos[ btun ]
      btun_info[ :wbuff ] << data
      add_write( btun )

      if btun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause dst #{ btun_info[ :domain_port ] }"
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
        puts "p#{ Process.pid } #{ Time.new } pause atun #{ dst_info[ :domain_port ] }"
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
    # deal with destination addr
    #
    def deal_with_destination_addr( ctl_addr, src_id, destination_addr, domain_port )
      dst = Socket.new( Addrinfo.new( destination_addr ).ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ domain_port } #{ e.class }"
        dst.close
        return
      end

      dst_id = dst.local_address.ip_port
      ctl_info = @ctl_infos[ ctl_addr ]

      @dst_infos[ dst ] = {
        id: dst_id,               # id
        ctl_addr: ctl_addr,       # 对应ctl
        im: ctl_info[ :im ],      # 标识
        domain_port: domain_port, # 目的地和端口
        rbuff: '',                # 对应的tun没准备好，暂存读到的流量
        atun: nil,                # 对应的atun
        btun: nil,                # 对应的btun
        wbuff: '',                # 从tun读到的流量
        src_id: src_id,           # 近端src id
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到新流量（由tun收到）的时间
        last_sent_at: nil,        # 上一次发出流量（由tun发出）的时间
        closing_write: false      # 准备关闭写
      }

      add_read( dst, :dst )

      ctl_info[ :dst_ids ][ src_id ] = dst_id
      ctl_info[ :dsts ][ dst_id ] = dst

      data = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
      # puts "debug add ctlmsg paired #{ src_id } #{ dst_id }"
      send_ctlmsg( data, ctl_addr )
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
          now = Time.new

          @ctl_infos.each do | ctl_addr, ctl_info |
            if now - ctl_info[ :last_recv_at ] >= EXPIRE_CTL
              puts "p#{ Process.pid } #{ Time.new } expire ctl #{ EXPIRE_CTL } #{ ctl_info[ :addrinfo ].inspect } tund ports #{ ctl_info[ :atund_port ] } #{ ctl_info[ :btund_port ] }"

              unless @deleting_ctl_infos.include?( ctl_addr ) then
                @deleting_ctl_infos << ctl_addr
                next_tick
              end
            end
          end

          @dst_infos.each do | dst, dst_info |
            last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
            last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]
            expire_after = dst_info[ :btun ] ? EXPIRE_AFTER : EXPIRE_NEW

            if ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after ) then
              puts "p#{ Process.pid } #{ Time.new } expire dst #{ expire_after } #{ dst_info[ :domain_port ] }"

              unless @closing_dsts.include?( dst ) then
                @closing_dsts << dst
                next_tick
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

          @paused_dsts.each do | dst |
            dst_info = @dst_infos[ dst ]
            btun = dst_info[ :btun ]

            if btun && !btun.closed? then
              btun_info = @btun_infos[ btun ]

              if btun_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain_port ] }"
                add_resume_dst( dst )
              end
            end
          end

          @paused_atuns.each do | atun |
            atun_info = @atun_infos[ atun ]
            dst = atun_info[ :dst ]

            if dst && !dst.closed? then
              dst_info = @dst_infos[ dst ]

              if dst_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume atun #{ atun_info[ :domain_port ] }"
                add_resume_atun( atun )
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

            if Time.new.day == RESET_TRAFF_DAY then
              puts "p#{ Process.pid } #{ Time.new } reset traffs"
              @traff_ins.transform_values!{ | _ | 0 }
              @traff_outs.transform_values!{ | _ | 0 }
            end
          end
        end
      end
    end

    ##
    # new a ctld
    #
    def new_a_ctld( proxyd_port )
      ctld = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      ctld.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      ctld.bind( Socket.sockaddr_in( proxyd_port, '0.0.0.0' ) )
      puts "p#{ Process.pid } #{ Time.new } ctld bind on #{ proxyd_port }"
      add_read( ctld, :ctld )
      @ctld = ctld
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
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund.listen( 127 )
      tund
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # resolve domain
    #
    def resolve_domain( ctl_addr, src_id, domain_port )
      resolv_cache = @resolv_caches[ domain_port ]

      if resolv_cache then
        destination_addr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain_port } hit resolv cache #{ Addrinfo.new( destination_addr ).inspect }"
          deal_with_destination_addr( ctl_addr, src_id, destination_addr, domain_port )
          return
        end

        # puts "debug expire #{ domain_port } resolv cache"
        @resolv_caches.delete( domain_port )
      end

      Thread.new do
        colon_idx = domain_port.rindex( ':' )

        if colon_idx then
          destination_domain = domain_port[ 0...colon_idx ]
          destination_port = domain_port[ ( colon_idx + 1 )..-1 ].to_i

          begin
            destination_addr = Socket.sockaddr_in( destination_port, destination_domain )
          rescue Exception => e
            puts "p#{ Process.pid } #{ Time.new } sockaddr in #{ domain_port } #{ e.class }"
          end
        end

        if destination_addr then
          # puts "debug resolved #{ domain_port } #{ Addrinfo.new( destination_addr ).inspect }"
          @resolv_caches[ domain_port ] = [ destination_addr, Time.new ]
          deal_with_destination_addr( ctl_addr, src_id, destination_addr, domain_port )
        end
      end
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( data, to_addr )
      begin
        @ctld.sendmsg( data, 0, to_addr )
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } sendmsg #{ e.class }"
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
      dotr.read_nonblock( 65535 )

      if @deleting_ctl_infos.any? then
        @deleting_ctl_infos.each { | ctl_addr | del_ctl_info( ctl_addr ) }
        @deleting_ctl_infos.clear
      end

      if @closing_dsts.any? then
        @closing_dsts.each { | dst | close_dst( dst ) }
        @closing_dsts.clear
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
    # read ctld
    #
    def read_ctld( ctld )
      data, addrinfo, rflags, *controls = ctld.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first
      ctl_addr = addrinfo.to_sockaddr
      ctl_info = @ctl_infos[ ctl_addr ]

      case ctl_num
      when HELLO then
        if ctl_info then
          atund_port, btund_port = ctl_info[ :atund_port ], ctl_info[ :btund_port ]
        else
          return if data.size <= 1
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
            addrinfo: addrinfo,          # 地址
            im: im,                      # 标识
            atund: atund,                # 对应atund，src->dst
            atund_port: atund_port,      # atund端口
            btund: btund,                # 对应btund，dst->src
            btund_port: btund_port,      # btund端口
            dsts: ConcurrentHash.new,    # dst_id => dst
            dst_ids: ConcurrentHash.new, # src_id => dst_id
            last_recv_at: Time.new       # 上一次收到流量的时间
          }

          puts "p#{ Process.pid } #{ Time.new } got hello #{ im.inspect }, atund listen on #{ atund_port }, btund listen on #{ btund_port }, ctl infos size #{ @ctl_infos.size }"
        end

        data2 = [ TUND_PORT, atund_port, btund_port ].pack( 'Cnn' )
        send_ctlmsg( data2, ctl_addr )
      when A_NEW_SOURCE then
        unless ctl_info then
          send_ctlmsg( [ UNKNOWN_CTL_ADDR ].pack( 'C' ), addrinfo )
          return
        end

        return if data.size <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        dst_id = ctl_info[ :dst_ids ][ src_id ]

        if dst_id then
          data2 = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
          # puts "debug dst id exist, send ctlmsg paired #{ src_id } #{ dst_id }"
          send_ctlmsg( data2, ctl_addr )
          return
        end

        domain_port = data[ 9..-1 ]
        # puts "debug got a new source #{ src_id } #{ domain_port }"
        resolve_domain( ctl_addr, src_id, domain_port )
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
        rescue IO::WaitWritable
          print 'w'
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
        data = dst.read_nonblock( 65535 )
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
      # puts "debug read dst #{ data.bytesize }, encode"
      data = @custom.encode( data )
      data = "#{ [ data.bytesize ].pack( 'n' ) }#{ data }"

      if btun then
        add_btun_wbuff( btun, data )
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
        domain_port: nil,                  # dst的目的地和端口
        rbuff: '',                         # 暂存当前块没收全的流量
        wait_bytes: 0                      # 还差多少字节收全当前块
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
        domain_port: nil,                  # dst的目的地和端口
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
        atun_info[ :domain_port ] = dst_info[ :domain_port ]
        dst_info[ :atun ] = atun

        data = data[ 2..-1 ]
      end

      until data.empty? do
        rbuff = atun_info[ :rbuff ]
        wait_bytes = atun_info[ :wait_bytes ]

        if wait_bytes > 0 then
          len = wait_bytes
          # puts "debug wait bytes #{ len }"
        else
          if data.bytesize <= 2 then
            # puts "debug unexpect data length #{ data.bytesize }"
            close_atun( atun )
            return
          end

          len = data[ 0, 2 ].unpack( 'n' ).first
          # puts "debug read len #{ len }"
          data = data[ 2..-1 ]
        end

        chunk = data[ 0, len ]
        chunk_size = chunk.bytesize

        if chunk_size == len then
          # 取完整了
          chunk = @custom.decode( "#{ rbuff }#{ chunk }" )
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
      btun_info[ :domain_port ] = dst_info[ :domain_port ]

      unless dst_info[ :rbuff ].empty? then
        # puts "debug move dst.rbuff to btun.wbuff"
        add_btun_wbuff( btun, dst_info[ :rbuff ] )
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
