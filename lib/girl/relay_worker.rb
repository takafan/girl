module Girl
  class RelayWorker

    ##
    # initialize
    #
    def initialize( resolv_port, nameserver, resolvd_port, redir_port, proxyd_host, proxyd_port, directs, remotes, im )
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @resolvd_addr = Socket.sockaddr_in( resolvd_port, proxyd_host )
      @qnames = remotes.map { | dom | dom.split( '.' ).map{ | sub | [ sub.size ].pack( 'C' ) + sub }.join }
      @proxyd_host = proxyd_host
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @directs = directs
      @remotes = remotes
      @custom = Girl::ProxyCustom.new( im )
      @resolv_custom = Girl::ResolvCustom.new
      @reads = []
      @writes = []
      @closing_rsvs = []
      @closing_srcs = []
      @paused_srcs = []
      @paused_dsts = []
      @paused_tuns = []
      @resume_srcs = []
      @resume_dsts = []
      @resume_tuns = []
      @roles = ConcurrentHash.new            # sock => :dotr / :resolv / :rsv / :redir / :proxy / :src / :dst / :tun
      @rsv_infos = ConcurrentHash.new        # rsv => {}
      @src_infos = ConcurrentHash.new        # src => {}
      @dst_infos = ConcurrentHash.new        # dst => {}
      @tun_infos = ConcurrentHash.new        # tun => {}
      @is_direct_caches = ConcurrentHash.new # ip => true / false
      @srcs = ConcurrentHash.new             # src_id => src
      @ip_address_list = Socket.ip_address_list

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_resolv( resolv_port )
      new_a_redir( redir_port )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire
      loop_check_resume

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          case @roles[ sock ]
          when :dotr then
            read_dotr( sock )
          when :resolv then
            read_resolv( sock )
          when :rsv then
            read_rsv( sock )
          when :redir then
            read_redir( sock )
          when :proxy then
            read_proxy( sock )
          when :src then
            read_src( sock )
          when :dst then
            read_dst( sock )
          when :tun then
            read_tun( sock )
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :proxy then
            write_proxy( sock )
          when :src then
            write_src( sock )
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
      if @proxy && !@proxy.closed? then
        # puts "debug1 send tun fin"
        data = [ TUN_FIN ].pack( 'C' )
        @proxy.write( data )
      end

      # puts "debug1 exit"
      exit
    end

    private

    ##
    # add a new source
    #
    def add_a_new_source( src )
      src_info = @src_infos[ src ]
      destination_domain = src_info[ :destination_domain ]
      destination_port = src_info[ :destination_port ]
      domain_port = [ destination_domain, destination_port ].join( ':' )
      data = "#{ [ A_NEW_SOURCE, src_info[ :id ] ].pack( 'CQ>' ) }#{ @custom.encode( domain_port ) }"
      add_ctlmsg( data )
    end

    ##
    # add closing src
    #
    def add_closing_src( src )
      return if src.closed? || @closing_srcs.include?( src )
      @closing_srcs << src
      next_tick
    end

    ##
    # add closing rsv
    #
    def add_closing_rsv( rsv )
      return if rsv.closed? || @closing_rsvs.include?( rsv )
      @closing_rsvs << rsv
      next_tick
    end

    ##
    # add ctlmsg
    #
    def add_ctlmsg( data )
      return if @proxy.nil? || @proxy.closed?
      @proxy_info[ :ctlmsgs ] << data
      add_write( @proxy )
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause direct src #{ dst_info[ :domain ] }"
        add_paused_src( dst_info[ :src ] )
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
    # add paused src
    #
    def add_paused_src( src )
      return if src.closed? || @paused_srcs.include?( src )
      @reads.delete( src )
      @paused_srcs << src
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
    # add resume src
    #
    def add_resume_src( src )
      return if @resume_srcs.include?( src )
      @resume_srcs << src
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
    # add socks5 conn reply
    #
    def add_socks5_conn_reply( src )
      # +----+-----+-------+------+----------+----------+
      # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      # +----+-----+-------+------+----------+----------+
      # | 1  |  1  | X'00' |  1   | Variable |    2     |
      # +----+-----+-------+------+----------+----------+
      redir_ip, redir_port = @redir_local_address.ip_unpack
      data = [ [ 5, 0, 0, 1 ].pack( 'C4' ), IPAddr.new( redir_ip ).hton, [ redir_port ].pack( 'n' ) ].join
      # puts "debug1 add src.wbuff socks5 conn reply #{ data.inspect }"
      add_src_wbuff( src, data )
    end

    ##
    # add src rbuff
    #
    def add_src_rbuff( src, data )
      src_info = @src_infos[ src ]
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug1 src.rbuff full"
        add_closing_src( src )
      end
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      return if src.closed? || @closing_srcs.include?( src )
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      src_info[ :last_recv_at ] = Time.new
      add_write( src )

      if src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          puts "p#{ Process.pid } #{ Time.new } pause dst #{ src_info[ :destination_domain ] }"
          add_paused_dst( dst )
        else
          tun = src_info[ :tun ]

          if tun then
            puts "p#{ Process.pid } #{ Time.new } pause tun #{ src_info[ :destination_domain ] }"
            add_paused_tun( tun )
          end
        end
      end
    end

    ##
    # add tun wbuff
    #
    def add_tun_wbuff( tun, data )
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause tunnel src #{ tun_info[ :domain ] }"
        add_paused_src( tun_info[ :src ] )
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
    # close proxy
    #
    def close_proxy( proxy )
      return if proxy.closed?
      # puts "debug1 close proxy"
      close_sock( proxy )
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
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close read src
    #
    def close_read_src( src )
      return if src.closed?
      # puts "debug1 close read src"
      src.close_read
      @reads.delete( src )

      if src.closed? then
        # puts "debug1 delete src info"
        @writes.delete( src )
        @roles.delete( src )
        src_info = del_src_info( src )
      else
        src_info = @src_infos[ src ]
      end

      src_info
    end

    ##
    # close read tun
    #
    def close_read_tun( tun )
      return if tun.closed?
      # puts "debug1 close read tun"
      tun.close_read
      @reads.delete( tun )

      if tun.closed? then
        # puts "debug1 delete tun info"
        @writes.delete( tun )
        @roles.delete( tun )
        tun_info = @tun_infos.delete( tun )
      else
        tun_info = @tun_infos[ tun ]
      end

      tun_info
    end

    ##
    # close rsv
    #
    def close_rsv( rsv )
      # puts "debug1 close rsv"
      rsv.close
      @reads.delete( rsv )
      @roles.delete( rsv )
      @rsv_infos.delete( rsv )
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
    # close src
    #
    def close_src( src )
      return if src.closed?
      # puts "debug1 close src"
      close_sock( src )
      src_info = del_src_info( src )
      dst = src_info[ :dst ]

      if dst then
        close_sock( dst )
        @dst_infos.delete( dst )
      else
        tun = src_info[ :tun ]

        if tun then
          close_sock( tun )
          @tun_infos.delete( tun )
        end
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
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close write src
    #
    def close_write_src( src )
      return if src.closed?
      # puts "debug1 close write src"
      src.close_write
      @writes.delete( src )

      if src.closed? then
        # puts "debug1 delete src info"
        @reads.delete( src )
        @roles.delete( src )
        src_info = del_src_info( src )
      else
        src_info = @src_infos[ src ]
      end

      src_info
    end

    ##
    # close write tun
    #
    def close_write_tun( tun )
      return if tun.closed?
      # puts "debug1 close write tun"
      tun.close_write
      @writes.delete( tun )

      if tun.closed? then
        # puts "debug1 delete tun info"
        @reads.delete( tun )
        @roles.delete( tun )
        tun_info = @tun_infos.delete( tun )
      else
        tun_info = @tun_infos[ tun ]
      end

      tun_info
    end

    ##
    # deal with destination ip
    #
    def deal_with_destination_ip( src, ip_info )
      return if src.closed?
      src_info = @src_infos[ src ]

      if ip_info.ipv4_loopback? \
        || ip_info.ipv6_loopback? \
        || ( ( @ip_address_list.any? { | addrinfo | addrinfo.ip_address == ip_info.ip_address } ) && ( src_info[ :destination_port ] == @redir_port ) ) then
        puts "p#{ Process.pid } #{ Time.new } ignore #{ ip_info.ip_address }:#{ src_info[ :destination_port ] }"
        add_closing_src( src )
        return
      end

      if ( src_info[ :destination_domain ] == @proxyd_host ) && ![ 80, 443 ].include?( src_info[ :destination_port ] ) then
        # 访问远端非80/443端口，直连
        puts "p#{ Process.pid } #{ Time.new } direct #{ ip_info.ip_address } #{ src_info[ :destination_port ] }"
        new_a_dst( src, ip_info )
        return
      end

      if @is_direct_caches.include?( ip_info.ip_address ) then
        is_direct = @is_direct_caches[ ip_info.ip_address ]
      else
        is_direct = @directs.any? { | direct | direct.include?( ip_info.ip_address ) }
        # 判断直连耗时较长（树莓派 0.27秒），这里可能切去主线程，回来src可能已关闭
        puts "p#{ Process.pid } #{ Time.new } cache is direct #{ ip_info.ip_address } #{ is_direct }"
        @is_direct_caches[ ip_info.ip_address ] = is_direct
      end

      if is_direct then
        # puts "debug1 #{ ip_info.inspect } hit directs"
        new_a_dst( src, ip_info )
      else
        # 走远端
        # puts "debug1 #{ ip_info.inspect } go tunnel"
        set_proxy_type_tunnel( src )
      end
    end

    ##
    # del src info
    #
    def del_src_info( src )
      src_info = @src_infos.delete( src )
      @srcs.delete( src_info[ :id ] )
      @proxy_info[ :pending_sources ].delete( src )

      src_info
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL
          now = Time.new

          if @proxy && !@proxy.closed? then
            if @proxy_info[ :last_recv_at ] then
              last_recv_at = @proxy_info[ :last_recv_at ]
              expire_after = EXPIRE_AFTER
            else
              last_recv_at = @proxy_info[ :created_at ]
              expire_after = EXPIRE_NEW
            end

            if now - last_recv_at >= expire_after then
              puts "p#{ Process.pid } #{ Time.new } expire proxy"
              @proxy_info[ :closing ] = true
              next_tick
            else
              # puts "debug1 #{ Time.new } send heartbeat"
              data = [ HEARTBEAT ].pack( 'C' )
              add_ctlmsg( data )
            end
          end

          @src_infos.each do | src, src_info |
            last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
            last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]
            expire_after = ( src_info[ :dst ] || src_info[ :tun ] ) ? EXPIRE_AFTER : EXPIRE_NEW

            if ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after ) then
              puts "p#{ Process.pid } #{ Time.new } expire src #{ expire_after } #{ src_info[ :destination_domain ] }"
              add_closing_src( src )

              unless src_info[ :rbuff ].empty? then
                puts "p#{ Process.pid } #{ Time.new } lost rbuff #{ src_info[ :rbuff ].inspect }"
              end
            end
          end

          @rsv_infos.each do | rsv, rsv_info |
            if ( now - rsv_info[ :created_at ] >= EXPIRE_NEW ) then
              puts "p#{ Process.pid } #{ Time.new } expire rsv #{ EXPIRE_NEW }"
              add_closing_rsv( rsv )
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

          @paused_srcs.each do | src |
            if src.closed? then
              add_resume_src( src )
            else
              src_info = @src_infos[ src ]
              dst = src_info[ :dst ]

              if dst then
                dst_info = @dst_infos[ dst ]

                if dst_info[ :wbuff ].size < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } resume direct src #{ src_info[ :destination_domain ] }"
                  add_resume_src( src )
                end
              else
                tun = src_info[ :tun ]
                tun_info = @tun_infos[ tun ]

                if tun_info[ :wbuff ].size < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } resume tunnel src #{ src_info[ :destination_domain ] }"
                  add_resume_src( src )
                end
              end
            end
          end

          @paused_dsts.each do | dst |
            if dst.closed? then
              add_resume_dst( dst )
            else
              dst_info = @dst_infos[ dst ]
              src = dst_info[ :src ]
              src_info = @src_infos[ src ]

              if src_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain ] }"
                add_resume_dst( dst )
              end
            end
          end

          @paused_tuns.each do | tun |
            if tun.closed? then
              add_resume_tun( tun )
            else
              tun_info = @tun_infos[ tun ]
              src = tun_info[ :src ]
              src_info = @src_infos[ src ]

              if src_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume tun #{ tun_info[ :domain ] }"
                add_resume_tun( tun )
              end
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( src, ip_info )
      return if src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      destination_addr = Socket.sockaddr_in( src_info[ :destination_port ], ip_info.ip_address )
      dst = Socket.new( ip_info.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 ) if RUBY_PLATFORM.include?( 'linux' )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dst connect destination #{ domain } #{ src_info[ :destination_port ] } #{ ip_info.ip_address } #{ e.class }, close src"
        dst.close
        add_closing_src( src )
        return
      end

      # puts "debug1 a new dst #{ dst.local_address.inspect }"
      dst_info = {
        src: src,            # 对应src
        domain: domain,      # 目的地
        wbuff: '',           # 写前
        closing_write: false # 准备关闭写
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :rbuff ] then
        # puts "debug1 move src.rbuff to dst.wbuff"
        dst_info[ :wbuff ] << src_info[ :rbuff ]
        add_write( dst )
      end
    end

    ##
    # new a proxy
    #
    def new_a_proxy
      proxy = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxy.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        proxy.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        proxy.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      proxy_info = {
        pending_sources: [],      # 还没配到tund，暂存的src
        ctlmsgs: [],              # ctlmsg
        tund_addr: nil,           # tund地址
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到流量的时间
        closing: false            # 是否准备关闭
      }

      begin
        proxy.connect_nonblock( @proxyd_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect proxyd #{ e.class }, close proxy"
        proxy.close
        return
      end

      @proxy = proxy
      @proxy_info = proxy_info
      add_read( proxy, :proxy )
      hello = @custom.hello
      puts "p#{ Process.pid } #{ Time.new } tunnel #{ hello.inspect }"
      data = "#{ [ HELLO ].pack( 'C' ) }#{ hello }"
      add_ctlmsg( data )
    end

    ##
    # new a redir
    #
    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 127 )
      puts "p#{ Process.pid } #{ Time.new } redir listen on #{ redir_port }"
      add_read( redir, :redir )
      @redir_port = redir_port
      @redir_local_address = redir.local_address
    end

    ##
    # new a resolv
    #
    def new_a_resolv( resolv_port )
      resolv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resolv.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resolv.bind( Socket.sockaddr_in( resolv_port, '0.0.0.0' ) )

      puts "p#{ Process.pid } #{ Time.new } resolv bind on #{ resolv_port }"
      add_read( resolv, :resolv )
      @resolv = resolv
    end

    ##
    # new a rsv
    #
    def new_a_rsv( src_addr, data )
      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      rsv.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      rsv.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      if @qnames.any? { | qname | data.include?( qname ) } then
        data = @resolv_custom.encode( data )
        to_addr = @resolvd_addr
      else
        to_addr = @nameserver_addr
      end

      puts "p#{ Process.pid } #{ Time.new } new a rsv to #{ Addrinfo.new( to_addr ).inspect }"

      @rsv_infos[ rsv ] = {
        src_addr: src_addr,
        created_at: Time.new
      }
      add_read( rsv, :rsv )
      send_data( rsv, to_addr, data )
    end

    ##
    # new a tun
    #
    def new_a_tun( src_id, dst_id )
      src = @srcs[ src_id ]
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :dst_id ]
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tun.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 ) if RUBY_PLATFORM.include?( 'linux' )

      begin
        tun.connect_nonblock( @proxy_info[ :tund_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect tund #{ e.class }"
        tun.close
        return
      end

      # puts "debug1 set tun.wbuff #{ dst_id }"
      data = [ dst_id ].pack( 'n' )

      unless src_info[ :rbuff ].empty? then
        # puts "debug1 encode and move src.rbuff to tun.wbuff"
        data << @custom.encode( src_info[ :rbuff ] )
      end

      domain = src_info[ :destination_domain ]
      @tun_infos[ tun ] = {
        src: src,            # 对应src
        domain: domain,      # 目的地
        wbuff: data,         # 写前
        closing_write: false # 准备关闭写
      }

      src_info[ :dst_id ] = dst_id
      src_info[ :tun ] = tun
      add_read( tun, :tun )
      add_write( tun )
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # send data
    #
    def send_data( sock, to_addr, data )
      begin
        sock.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        puts "p#{ Process.pid } #{ Time.new } sendmsg to #{ to_addr.ip_unpack.inspect } #{ e.class }"
      end
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set proxy type tunnel
    #
    def set_proxy_type_tunnel( src )
      return if src.closed?
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :tunnel
      src_id = src_info[ :id ]

      if @proxy_info[ :tund_addr ] then
        add_a_new_source( src )
      else
        @proxy_info[ :pending_sources ] << src
      end
    end

    ##
    # set src closing write
    #
    def set_src_closing_write( src )
      return if src.closed? || @closing_srcs.include?( src )
      src_info = @src_infos[ src ]
      return if src_info[ :closing_write ]
      src_info[ :closing_write ] = true
      add_write( src )
    end

    ##
    # set tun closing write
    #
    def set_tun_closing_write( tun )
      return if tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing_write ]
      tun_info[ :closing_write ] = true
      add_write( tun )
    end

    ##
    # sub http request
    #
    def sub_http_request( data )
      lines = data.split( "\r\n" )

      return [ data, nil ] if lines.empty?

      method, url, proto = lines.first.split( ' ' )

      if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://' then
        domain_port = url.split( '/' )[ 2 ]
        data = data.sub( "http://#{ domain_port }", '' )
        # puts "debug1 subed #{ data.inspect } #{ domain_port }"
      end

      [ data, domain_port ]
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )

      if @proxy && !@proxy.closed? && @proxy_info[ :closing ] then
        close_proxy( @proxy )
      end

      if @closing_rsvs.any? then
        @closing_rsvs.each { | rsv | close_rsv( rsv ) }
        @closing_rsvs.clear
      end

      if @closing_srcs.any? then
        @closing_srcs.each { | src | close_src( src ) }
        @closing_srcs.clear
      end

      if @resume_srcs.any? then
        @resume_srcs.each do | src |
          add_read( src )
          @paused_srcs.delete( src )
        end

        @resume_srcs.clear
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
    # read resolv
    #
    def read_resolv( resolv )
      data, addrinfo, rflags, *controls = resolv.recvmsg
      # puts "debug1 resolv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      new_a_rsv( addrinfo.to_sockaddr, data )
    end

    ##
    # read rsv
    #
    def read_rsv( rsv )
      data, addrinfo, rflags, *controls = rsv.recvmsg
      # puts "debug1 rsv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"

      if addrinfo.to_sockaddr == @resolvd_addr then
        data = @resolv_custom.decode( data )
      end

      rsv_info = @rsv_infos[ rsv ]
      send_data( @resolv, rsv_info[ :src_addr ], data )
      close_rsv( rsv )
    end

    ##
    # read redir
    #
    def read_redir( redir )
      begin
        src, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      end

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = src.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class }"
        src.close
      end

      dest_family, dest_port, dest_host = option.unpack( 'nnN' )
      dest_addr = Socket.sockaddr_in( dest_port, dest_host )
      dest_addrinfo = Addrinfo.new( dest_addr )
      dest_ip = dest_addrinfo.ip_address

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug1 accept a src #{ addrinfo.ip_unpack.inspect } to #{ dest_ip }:#{ dest_port } #{ src_id }"

      @srcs[ src_id ] = src
      @src_infos[ src ] = {
        id: src_id,                  # id
        proxy_type: :checking,       # :checking / :direct / :tunnel
        destination_domain: dest_ip, # 目的地域名
        destination_port: dest_port, # 目的地端口
        rbuff: '',                   # 读到的流量
        dst: nil,                    # :direct的场合，对应的dst
        tun: nil,                    # :tunnel的场合，对应的tun
        dst_id: nil,                 # 远端dst id
        wbuff: '',                   # 从dst/tun读到的流量
        created_at: Time.new,        # 创建时间
        last_recv_at: nil,           # 上一次收到新流量（由dst收到，或者由tun收到）的时间
        last_sent_at: nil,           # 上一次发出流量（由dst发出，或者由tun发出）的时间
        closing_write: false         # 准备关闭写
      }

      add_read( src, :src )

      # 避免多线程重复建proxy，在accept到src时就建。
      if @proxy.nil? || @proxy.closed? then
        new_a_proxy
      end

      deal_with_destination_ip( src, dest_addrinfo )
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
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read proxy #{ e.class }"
        close_proxy( proxy )
        return
      end

      @proxy_info[ :last_recv_at ] = Time.new

      data.split( SEPARATE ).each do | ctlmsg |
        next unless ctlmsg[ 0 ]

        ctl_num = ctlmsg[ 0 ].unpack( 'C' ).first

        case ctl_num
        when TUND_PORT then
          next if @proxy_info[ :tund_addr ] || ( ctlmsg.size != 3 )
          tund_port = ctlmsg[ 1, 2 ].unpack( 'n' ).first
          puts "p#{ Process.pid } #{ Time.new } got tund port #{ tund_port }"
          @proxy_info[ :tund_addr ] = Socket.sockaddr_in( tund_port, @proxyd_host )

          if @proxy_info[ :pending_sources ].any? then
            puts "p#{ Process.pid } #{ Time.new } send pending sources"
            @proxy_info[ :pending_sources ].each { | src | add_a_new_source( src ) }
            @proxy_info[ :pending_sources ].clear
          end
        when PAIRED then
          next if ctlmsg.size != 11
          src_id, dst_id = ctlmsg[ 1, 10 ].unpack( 'Q>n' )
          # puts "debug1 got paired #{ src_id } #{ dst_id }"
          new_a_tun( src_id, dst_id )
        when TUND_FIN then
          puts "p#{ Process.pid } #{ Time.new } got tund fin"
          close_proxy( proxy )
          return
        when HEARTBEAT
          # puts "debug1 #{ Time.new } got heartbeat"
        end
      end
    end

    ##
    # read src
    #
    def read_src( src )
      if src.closed? then
        puts "p#{ Process.pid } #{ Time.new } read src but src closed?"
        return
      end

      begin
        data = src.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read src #{ e.class }"
        src_info = close_read_src( src )
        dst = src_info[ :dst ]

        if dst then
          set_dst_closing_write( dst )
        else
          tun = src_info[ :tun ]
          set_tun_closing_write( tun ) if tun
        end

        return
      end

      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :checking then
        # puts "debug1 add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :tunnel then
        tun = src_info[ :tun ]

        if tun then
          unless tun.closed? then
            data = @custom.encode( data )
            # puts "debug2 add tun.wbuff encoded #{ data.bytesize }"
            add_tun_wbuff( tun, data )
          end
        else
          # puts "debug1 tun not ready, save data to src.rbuff"
          add_src_rbuff( src, data )
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          unless dst.closed? then
            # puts "debug2 add dst.wbuff #{ data.bytesize }"
            add_dst_wbuff( dst, data )
          end
        else
          # puts "debug1 dst not ready, save data to src.rbuff"
          add_src_rbuff( src, data )
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
        src = dst_info[ :src ]
        set_src_closing_write( src )
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]
      add_src_wbuff( src, data )
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
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read tun #{ e.class }"
        tun_info = close_read_tun( tun )
        src = tun_info[ :src ]
        set_src_closing_write( src )
        return
      end

      tun_info = @tun_infos[ tun ]
      src = tun_info[ :src ]
      data = @custom.decode( data )
      # puts "debug2 add src.wbuff decoded #{ data.bytesize }"
      add_src_wbuff( src, data )
    end

    ##
    # write proxy
    #
    def write_proxy( proxy )
      if proxy.closed? then
        puts "p#{ Process.pid } #{ Time.new } write proxy but proxy closed?"
        return
      end

      if @proxy_info[ :ctlmsgs ].any? then
        data = @proxy_info[ :ctlmsgs ].map{ | ctlmsg | "#{ ctlmsg }#{ SEPARATE }" }.join

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

        @proxy_info[ :ctlmsgs ].clear
      end

      @writes.delete( proxy )
    end

    ##
    # write src
    #
    def write_src( src )
      if src.closed? then
        puts "p#{ Process.pid } #{ Time.new } write src but src closed?"
        return
      end

      src_info = @src_infos[ src ]
      dst = src_info[ :dst ]
      data = src_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if src_info[ :closing_write ] then
          close_write_src( src )
        else
          @writes.delete( src )
        end

        return
      end

      # 写入
      begin
        written = src.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write src #{ e.class }"
        close_write_src( src )

        if dst then
          close_read_dst( dst )
        else
          tun = src_info[ :tun ]
          close_read_tun( tun ) if tun
        end

        return
      end

      # puts "debug2 written src #{ written }"
      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
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
      src = dst_info[ :src ]
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
        close_read_src( src )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data

      unless src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
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
      src = tun_info[ :src ]
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
        close_read_src( src )
        return
      end

      # puts "debug2 written tun #{ written }"
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data

      unless src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
