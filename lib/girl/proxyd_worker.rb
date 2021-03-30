module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port, cert_path, key_path )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @closing_proxys = []
      @closing_dsts = []
      @closing_tuns = []
      @paused_dsts = []
      @paused_tuns = []
      @resume_dsts = []
      @resume_tuns = []
      @roles = ConcurrentHash.new         # sock => :dotr / :proxyd / :proxy / :infod / :dst / :tund / :tun
      @proxy_infos = ConcurrentHash.new   # proxy => {}
      @dst_infos = ConcurrentHash.new     # dst => {}
      @tund_infos = ConcurrentHash.new    # tund => {}
      @tun_infos = ConcurrentHash.new     # tun => {}
      @resolv_caches = ConcurrentHash.new # domain => [ ip, created_at ]
      @traff_ins = ConcurrentHash.new     # im => 0
      @traff_outs = ConcurrentHash.new    # im => 0

      cert = OpenSSL::X509::Certificate.new File.read( cert_path )
      key = OpenSSL::PKey::RSA.new File.read( key_path )
      context = OpenSSL::SSL::SSLContext.new
      context.add_certificate( cert, key )
      @context = context

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_proxyd( proxyd_port )
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
          when :proxyd then
            read_proxyd( sock )
          when :proxy then
            read_proxy( sock )
          when :infod then
            read_infod( sock )
          when :dst then
            read_dst( sock )
          when :tund then
            read_tund( sock )
          when :tun then
            read_tun( sock )
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :proxy then
            write_proxy( sock )
          when :dst then
            write_dst( sock )
          when :tun then
            write_tun( sock )
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
      @proxy_infos.keys.each do | proxy |
        # puts "debug1 send tund fin"
        data = [ TUND_FIN ].pack( 'C' )
        proxy.write( data )
      end

      # puts "debug1 exit"
      exit
    end

    private

    ##
    # add ctlmsg
    #
    def add_ctlmsg( proxy, data )
      return if proxy.closed? || @closing_proxys.include?( proxy )
      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :ctlmsgs ] << data
      add_write( proxy )
    end

    ##
    # add dst rbuff
    #
    def add_dst_rbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :rbuff ] << data

      if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug1 dst.rbuff full"
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
        puts "p#{ Process.pid } #{ Time.new } pause tun #{ dst_info[ :domain_port ] }"
        add_paused_tun( dst_info[ :tun ] )
      end
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
    # add paused tun
    #
    def add_paused_tun( tun )
      return if tun.closed? || @paused_tuns.include?( tun )
      @reads.delete( tun )
      @paused_tuns << tun
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
    # add resume dst
    #
    def add_resume_dst( dst )
      return if @resume_dsts.include?( dst )
      @resume_dsts << dst
      next_tick
    end

    ##
    # add resume tun
    #
    def add_resume_tun( tun )
      return if @resume_tuns.include?( tun )
      @resume_tuns << tun
      next_tick
    end

    ##
    # add tun wbuff
    #
    def add_tun_wbuff( tun, data )
      return if tun.closed? || @closing_tuns.include?( tun )
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause dst #{ tun_info[ :domain_port ] }"
        add_paused_dst( tun_info[ :dst ] )
      end
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
    # close dst
    #
    def close_dst( dst )
      return if dst.closed?
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = del_dst_info( dst )
      tun = dst_info[ :tun ]

      if tun then
        close_sock( tun )
        @tun_infos.delete( tun )
      end
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.closed?
      # puts "debug1 close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        # puts "debug1 delete dst info"
        @writes.delete( dst )
        @roles.delete( dst )
        dst_info = del_dst_info( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close read tun
    #
    def close_read_tun( tun )
      return if tun.closed?
      # puts "debug1 close read tun"
      tun_info = @tun_infos[ tun ]
      tun_info[ :close_read ] = true

      if tun_info[ :close_write ] then
        # puts "debug1 close tun"
        close_sock( tun )
        tun_info = @tun_infos.delete( tun )
      else
        @reads.delete( tun )
      end

      tun_info
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
    # close tun
    #
    def close_tun( tun )
      return if tun.closed?
      # puts "debug1 close tun"
      close_sock( tun )
      tun_info = @tun_infos.delete( tun )
      dst = tun_info[ :dst ]

      if dst then
        close_sock( dst )
        del_dst_info( dst )
      end
    end

    ##
    # close proxy
    #
    def close_proxy( proxy )
      return if proxy.closed?
      # puts "debug1 close proxy"
      close_sock( proxy )
      proxy_info = @proxy_infos.delete( proxy )
      tund = proxy_info[ :tund ]

      if tund then
        close_sock( tund )
        @tund_infos.delete( tund )
      end
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.closed?
      # puts "debug1 close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        # puts "debug1 delete dst info"
        @reads.delete( dst )
        @roles.delete( dst )
        dst_info = del_dst_info( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close write tun
    #
    def close_write_tun( tun )
      return if tun.closed?
      # puts "debug1 close write tun"
      tun_info = @tun_infos[ tun ]
      tun_info[ :close_write ] = true

      if tun_info[ :close_read ] then
        # puts "debug1 close tun"
        close_sock( tun )
        tun_info = @tun_infos.delete( tun )
      else
        @writes.delete( tun )
      end

      tun_info
    end

    ##
    # deal with destination addr
    #
    def deal_with_destination_addr( proxy, src_id, destination_addr, domain_port )
      dst = Socket.new( Addrinfo.new( destination_addr ).ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ domain_port } #{ e.class }"
        dst.close
        return
      end

      dst_id = dst.local_address.ip_port
      proxy_info = @proxy_infos[ proxy ]

      @dst_infos[ dst ] = {
        id: dst_id,               # id
        proxy: proxy,             # 对应proxy
        im: proxy_info[ :im ],    # 标识
        domain_port: domain_port, # 目的地和端口
        rbuff: '',                # 对应的tun没准备好，暂存读到的流量
        tun: nil,                 # 对应的tun
        wbuff: '',                # 从tun读到的流量
        src_id: src_id,           # 近端src id
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到新流量（由tun收到）的时间
        last_sent_at: nil,        # 上一次发出流量（由tun发出）的时间
        closing_write: false      # 准备关闭写
      }

      add_read( dst, :dst )

      proxy_info[ :dst_ids ][ src_id ] = dst_id
      proxy_info[ :dsts ][ dst_id ] = dst

      data = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
      # puts "debug1 add ctlmsg paired #{ src_id } #{ dst_id }"
      add_ctlmsg( proxy, data )
    end

    ##
    # del dst info
    #
    def del_dst_info( dst )
      dst_info = @dst_infos.delete( dst )
      proxy = dst_info[ :proxy ]

      unless proxy.closed? then
        proxy_info = @proxy_infos[ proxy ]
        proxy_info[ :dsts ].delete( dst_info[ :id ] )
        proxy_info[ :dst_ids ].delete( dst_info[ :src_id ] )
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

          @proxy_infos.each do | proxy, proxy_info |
            last_recv_at = proxy_info[ :last_recv_at ] || proxy_info[ :created_at ]

            if proxy_info[ :dsts ].empty? && ( now - last_recv_at >= EXPIRE_AFTER ) then
              puts "p#{ Process.pid } #{ Time.new } expire proxy #{ proxy_info[ :addrinfo ].inspect }"

              unless @closing_proxys.include?( proxy ) then
                @closing_proxys << proxy
                next_tick
              end
            end
          end

          @dst_infos.each do | dst, dst_info |
            last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
            last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]
            expire_after = dst_info[ :tun ] ? EXPIRE_AFTER : EXPIRE_NEW

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
            if dst.closed? then
              add_resume_dst( dst )
            else
              dst_info = @dst_infos[ dst ]
              tun = dst_info[ :tun ]
              tun_info = @tun_infos[ tun ]

              if tun_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain_port ] }"
                add_resume_dst( dst )
              end
            end
          end

          @paused_tuns.each do | tun |
            if tun.closed? then
              add_resume_tun( tun )
            else
              tun_info = @tun_infos[ tun ]
              dst = tun_info[ :dst ]
              dst_info = @dst_infos[ dst ]

              if dst_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume tun #{ tun_info[ :domain_port ] }"
                add_resume_tun( tun )
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
    # new a proxyd
    #
    def new_a_proxyd( proxyd_port )
      proxyd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxyd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      proxyd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      proxyd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      proxyd.bind( Socket.sockaddr_in( proxyd_port, '0.0.0.0' ) )
      proxyd.listen( 127 )
      puts "p#{ Process.pid } #{ Time.new } proxyd bind on #{ proxyd_port }"
      ssl_proxyd = OpenSSL::SSL::SSLServer.new proxyd, @context
      add_read( ssl_proxyd, :proxyd )
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
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # resolve domain
    #
    def resolve_domain( proxy, src_id, domain_port )
      resolv_cache = @resolv_caches[ domain_port ]

      if resolv_cache then
        destination_addr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug1 #{ domain_port } hit resolv cache #{ Addrinfo.new( destination_addr ).inspect }"
          deal_with_destination_addr( proxy, src_id, destination_addr, domain_port )
          return
        end

        # puts "debug1 expire #{ domain_port } resolv cache"
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
          # puts "debug1 resolved #{ domain_port } #{ Addrinfo.new( destination_addr ).inspect }"
          @resolv_caches[ domain_port ] = [ destination_addr, Time.new ]

          unless proxy.closed? then
            deal_with_destination_addr( proxy, src_id, destination_addr, domain_port )
          end
        end
      end
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed? || @closing_dsts.include?( dst )
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set tun closing write
    #
    def set_tun_closing_write( tun )
      return if tun.closed? || @closing_tuns.include?( tun )
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing_write ]
      tun_info[ :closing_write ] = true
      add_write( tun )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )

      # 处理关闭
      if @closing_proxys.any? then
        @closing_proxys.each { | proxy | close_proxy( proxy ) }
        @closing_proxys.clear
      end

      if @closing_dsts.any? then
        @closing_dsts.each { | dst | close_dst( dst ) }
        @closing_dsts.clear
      end

      if @closing_tuns.any? then
        @closing_tuns.each { | tun | close_tun( tun ) }
        @closing_tuns.clear
      end

      if @resume_dsts.any? then
        @resume_dsts.each do | dst |
          add_read( dst )
          @paused_dsts.delete( dst )
        end

        @resume_dsts.clear
      end

      if @resume_tuns.any? then
        @resume_tuns.each do | tun |
          add_read( tun )
          @paused_tuns.delete( tun )
        end

        @resume_tuns.clear
      end
    end

    ##
    # read proxyd
    #
    def read_proxyd( proxyd )
      begin
        proxy = proxyd.accept
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } proxyd accept #{ e.class }"
        return
      end

      @proxy_infos[ proxy ] = {
        addrinfo: proxy.io.remote_address, # proxy地址
        im: nil,                        # 标识
        tund: nil,                      # 对应tund
        tund_port: nil,                 # tund端口
        ctlmsgs: [],                    # ctlmsg
        dsts: ConcurrentHash.new,       # dst_id => dst
        dst_ids: ConcurrentHash.new,    # src_id => dst_id
        created_at: Time.new,           # 创建时间
        last_recv_at: nil               # 上一次收到流量的时间
      }

      puts "p#{ Process.pid } #{ Time.new } accept a proxy #{ proxy.io.remote_address.inspect } #{ proxy.ssl_version }, #{ @proxy_infos.size } proxys"
      add_read( proxy, :proxy )
    end

    ##
    # read proxy
    #
    def read_proxy( proxy )
      if proxy.closed? then
        puts "p#{ Process.pid } #{ Time.new } read proxy but proxy closed?"
        return
      end

      begin
        data = proxy.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable
        return
      rescue Errno::EINTR
        puts e.class
        return
      rescue Exception => e
        # puts "debug1 read proxy #{ e.class }"
        close_proxy( proxy )
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :last_recv_at ] = Time.new

      data.split( SEPARATE ).each do | ctlmsg |
        next unless ctlmsg[ 0 ]

        ctl_num = ctlmsg[ 0 ].unpack( 'C' ).first

        case ctl_num
        when HELLO then
          next if proxy_info[ :tund_port ] || ctlmsg.size <= 1
          im = ctlmsg[ 1..-1 ]
          addrinfo = proxy_info[ :addrinfo ]
          result = @custom.check( im, addrinfo )

          if result != :success then
            puts "p#{ Process.pid } #{ Time.new } #{ result }"
            return
          end

          unless @traff_ins.include?( im ) then
            @traff_ins[ im ] = 0
            @traff_outs[ im ] = 0
          end

          tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
          tund.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
          tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
          tund_port = tund.local_address.ip_port
          tund.listen( 127 )
          puts "p#{ Process.pid } #{ Time.new } tund #{ im.inspect } bind on #{ tund_port }"
          ssl_tund = OpenSSL::SSL::SSLServer.new tund, @context
          add_read( ssl_tund, :tund )

          @tund_infos[ ssl_tund ] = {
            proxy: proxy,
            close_read: false,
            close_write: false
          }

          proxy_info[ :im ] = im
          proxy_info[ :tund ] = ssl_tund
          proxy_info[ :tund_port ] = tund_port
          data2 = [ TUND_PORT, tund_port ].pack( 'Cn' )
          add_ctlmsg( proxy, data2 )
        when A_NEW_SOURCE then
          next if ctlmsg.size <= 9
          src_id = ctlmsg[ 1, 8 ].unpack( 'Q>' ).first
          dst_id = proxy_info[ :dst_ids ][ src_id ]
          next if dst_id
          domain_port = ctlmsg[ 9..-1 ]
          # puts "debug1 a new source #{ src_id } #{ domain_port }"
          resolve_domain( proxy, src_id, domain_port )
        when RESOLV then
          next if ctlmsg.size <= 9
          src_id = ctlmsg[ 1, 8 ].unpack( 'Q>' ).first
          domain = ctlmsg[ 9..-1 ]

          Thread.new do
            begin
              ip_info = Addrinfo.ip( domain )
            rescue Exception => e
              puts "p#{ Process.pid } #{ Time.new } resolv #{ domain.inspect } #{ e.class }"
            end

            if ip_info then
              ip = ip_info.ip_address
              puts "p#{ Process.pid } #{ Time.new } resolved #{ domain } #{ ip }"
              data2 = "#{ [ RESOLVED, src_id ].pack( 'CQ>' ) }#{ ip }"
              add_ctlmsg( proxy, data2 )
            end
          end
        when TUN_FIN then
          puts "p#{ Process.pid } #{ Time.new } got tun fin"
          close_proxy( proxy )
          return
        when HEARTBEAT
          # puts "debug1 #{ Time.new } got heartbeat"
          data2 = [ HEARTBEAT ].pack( 'C' )
          add_ctlmsg( proxy, data2 )
        end
      end
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first
      # puts "debug1 infod got #{ ctl_num } #{ addrinfo.ip_unpack.inspect }"

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
        rescue IO::WaitWritable, Errno::EINTR
          print 'w'
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
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

      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        dst_info = close_read_dst( dst )
        tun = dst_info[ :tun ]
        set_tun_closing_write( tun ) if tun
        return
      end

      dst_info = @dst_infos[ dst ]
      @traff_ins[ dst_info[ :im ] ] += data.bytesize
      tun = dst_info[ :tun ]

      if tun then
        unless tun.closed? then
          tun_info = @tun_infos[ tun ]
          # puts "debug2 add tun.wbuff #{ data.bytesize }"
          add_tun_wbuff( tun, data )
        end
      else
        add_dst_rbuff( dst, data )
      end
    end

    ##
    # read tund
    #
    def read_tund( tund )
      if tund.closed? then
        puts "p#{ Process.pid } #{ Time.new } read tund but tund closed?"
        return
      end

      begin
        tun = tund.accept
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } tund accept #{ e.class }"
        return
      end

      # puts "debug1 accept a tun #{ tun.ssl_version }"
      tund_info = @tund_infos[ tund ]
      proxy = tund_info[ :proxy ]
      proxy_info = @proxy_infos[ proxy ]

      @tun_infos[ tun ] = {
        proxy: proxy,          # 对应proxy
        im: proxy_info[ :im ], # 标识
        dst: nil,              # 对应dst
        domain_port: nil,      # dst的目的地和端口
        wbuff: '',             # 写前
        closing_write: false   # 准备关闭写
      }

      add_read( tun, :tun )
    end

    ##
    # read tun
    #
    def read_tun( tun )
      if tun.closed? then
        puts "p#{ Process.pid } #{ Time.new } read tun but tun closed?"
        return
      end

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable
        return
      rescue Errno::EINTR
        puts e.class
        return
      rescue Exception => e
        # puts "debug1 read tun #{ e.class }"
        tun_info = close_read_tun( tun )
        dst = tun_info[ :dst ]
        set_dst_closing_write( dst ) if dst
        return
      end

      tun_info = @tun_infos[ tun ]
      @traff_ins[ tun_info[ :im ] ] += data.bytesize
      dst = tun_info[ :dst ]

      unless dst then
        dst_id = data[ 0, 2 ].unpack( 'n' ).first
        proxy = tun_info[ :proxy ]

        if proxy.closed? then
          close_tun( tun )
          return
        end

        proxy_info = @proxy_infos[ proxy ]
        dst = proxy_info[ :dsts ][ dst_id ]

        unless dst then
          close_tun( tun )
          return
        end

        # puts "debug1 set tun.dst #{ dst_id }"
        tun_info[ :dst ] = dst
        dst_info = @dst_infos[ dst ]
        tun_info[ :domain_port ] = dst_info[ :domain_port ]

        unless dst_info[ :rbuff ].empty? then
          # puts "debug1 move dst.rbuff to tun.wbuff"
          add_tun_wbuff( tun, dst_info[ :rbuff ] )
        end

        dst_info[ :tun ] = tun
        data = data[ 2..-1 ]
        return if data.empty?
      end

      # puts "debug2 add dst.wbuff #{ data.bytesize }"
      add_dst_wbuff( dst, data )
    end

    ##
    # write proxy
    #
    def write_proxy( proxy )
      proxy_info = @proxy_infos[ proxy ]

      # 发ctlmsg
      while proxy_info[ :ctlmsgs ].any? do
        data = proxy_info[ :ctlmsgs ].map{ | ctlmsg | "#{ ctlmsg }#{ SEPARATE }" }.join

        # 写入
        begin
          written = proxy.write( data )
        rescue IO::WaitWritable, Errno::EINTR
          print 'w'
          return
        rescue Exception => e
          # puts "debug1 write proxy #{ e.class }"
          close_proxy( proxy )
          return
        end

        proxy_info[ :ctlmsgs ].clear
      end

      @writes.delete( proxy )
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
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write dst #{ e.class }"
        close_write_dst( dst )
        close_read_tun( tun ) if tun
        return
      end

      # puts "debug2 written dst #{ written }"
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @traff_outs[ dst_info[ :im ] ] += written
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if tun.closed? then
        puts "p#{ Process.pid } #{ Time.new } write tun but tun closed?"
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
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write tun #{ e.class }"
        close_write_tun( tun )
        close_read_dst( dst ) if dst
        return
      end

      # puts "debug2 written tun #{ written }"
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data
      @traff_outs[ tun_info[ :im ] ] += written

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]
        dst_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
