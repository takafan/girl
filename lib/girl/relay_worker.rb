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
      @paused_btuns = []
      @resume_srcs = []
      @resume_dsts = []
      @resume_btuns = []
      @pending_srcs = []                     # 还没配到tund，暂存的src
      @roles = ConcurrentHash.new            # sock => :dotr / :resolv / :rsv / :redir / :proxy / :src / :dst / :atun / :btun
      @rsv_infos = ConcurrentHash.new        # rsv => {}
      @src_infos = ConcurrentHash.new        # src => {}
      @dst_infos = ConcurrentHash.new        # dst => {}
      @atun_infos = ConcurrentHash.new       # atun => {}
      @btun_infos = ConcurrentHash.new       # btun => {}
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
          when :ctl then
            read_ctl( sock )
          when :src then
            read_src( sock )
          when :dst then
            read_dst( sock )
          when :btun then
            read_btun( sock )
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :src then
            write_src( sock )
          when :dst then
            write_dst( sock )
          when :atun then
            write_atun( sock )
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
      send_ctlmsg( [ CTL_FIN ].pack( 'C' ) )
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
      # puts "debug add a new source #{ src_info[ :id ] } #{ domain_port }"
      key = [ A_NEW_SOURCE, src_info[ :id ] ].pack( 'CQ>' )
      add_ctlmsg( key, domain_port )
    end

    ##
    # add atun wbuff
    #
    def add_atun_wbuff( atun, data )
      return if atun.closed?
      atun_info = @atun_infos[ atun ]
      atun_info[ :wbuff ] << data
      add_write( atun )

      if atun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause tunnel src #{ atun_info[ :domain ] }"
        add_paused_src( atun_info[ :src ] )
      end
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
    def add_ctlmsg( key, data )
      ctlmsg = "#{ key }#{ data }"
      send_ctlmsg( ctlmsg )
      @ctl_info[ :resends ][ key ] = 0
      loop_resend_ctlmsg( key, ctlmsg )
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause direct src #{ dst_info[ :domain ] }"
        add_paused_src( dst_info[ :src ] )
      end
    end

    ##
    # add paused btun
    #
    def add_paused_btun( btun )
      return if btun.closed? || @paused_btuns.include?( btun )
      @reads.delete( btun )
      @paused_btuns << btun
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
    # add resume btun
    #
    def add_resume_btun( btun )
      return if @resume_btuns.include?( btun )
      @resume_btuns << btun
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
    # add src rbuff
    #
    def add_src_rbuff( src, data )
      src_info = @src_infos[ src ]
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug src.rbuff full"
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
          btun = src_info[ :btun ]

          if btun then
            puts "p#{ Process.pid } #{ Time.new } pause btun #{ src_info[ :destination_domain ] }"
            add_paused_btun( btun )
          end
        end
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
    # close atun
    #
    def close_atun( atun )
      return if atun.closed?
      # puts "debug close atun"
      close_sock( atun )
      @atun_infos.delete( atun )
    end

    ##
    # close btun
    #
    def close_btun( btun )
      return if btun.closed?
      # puts "debug close btun"
      close_sock( btun )
      @btun_infos.delete( btun )
      @paused_btuns.delete( btun )
      @resume_btuns.delete( btun )
    end

    ##
    # close ctl
    #
    def close_ctl( ctl )
      close_sock( ctl )
      @ctl_info[ :resends ].clear
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
        @dst_infos.delete( dst )
      end
    end

    ##
    # close read src
    #
    def close_read_src( src )
      return if src.closed?
      # puts "debug close read src"
      src.close_read
      @reads.delete( src )

      if src.closed? then
        @writes.delete( src )
        @roles.delete( src )
        del_src_info( src )
      end
    end

    ##
    # close rsv
    #
    def close_rsv( rsv )
      # puts "debug close rsv"
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
      # puts "debug close src"
      close_sock( src )
      src_info = del_src_info( src )
      dst = src_info[ :dst ]

      if dst then
        close_sock( dst )
        del_dst_info( dst )
      else
        atun = src_info[ :atun ]
        btun = src_info[ :btun ]

        if atun then
          close_atun( atun )
        end

        if btun then
          close_btun( btun )
        end
      end
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
        del_dst_info( dst )
      end
    end

    ##
    # close write src
    #
    def close_write_src( src )
      return if src.closed?
      # puts "debug close write src"
      src.close_write
      @writes.delete( src )

      if src.closed? then
        @reads.delete( src )
        @roles.delete( src )
        del_src_info( src )
      end
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
        # puts "debug #{ ip_info.inspect } hit directs"
        new_a_dst( src, ip_info )
      else
        # 走远端
        # puts "debug #{ ip_info.inspect } go tunnel"
        set_proxy_type_tunnel( src )
      end
    end

    ##
    # del dst info
    #
    def del_dst_info( dst )
      # puts "debug delete dst info"
      dst_info = @dst_infos.delete( dst )
      @paused_dsts.delete( dst )
      @resume_dsts.delete( dst )
      dst_info
    end

    ##
    # del src info
    #
    def del_src_info( src )
      # puts "debug delete src info"
      src_info = @src_infos.delete( src )
      @srcs.delete( src_info[ :id ] )
      @pending_srcs.delete( src )
      @paused_srcs.delete( src )
      @resume_srcs.delete( src )
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

          if @ctl && !@ctl.closed? then
            last_recv_at = @ctl_info[ :last_recv_at ] || @ctl_info[ :created_at ]

            if now - last_recv_at >= EXPIRE_AFTER then
               puts "p#{ Process.pid } #{ Time.new } expire ctl"
               @ctl_info[ :closing ] = true
               next_tick
            end
          end

          @rsv_infos.each do | rsv, rsv_info |
            if ( now - rsv_info[ :created_at ] >= EXPIRE_NEW ) then
              puts "p#{ Process.pid } #{ Time.new } expire rsv #{ EXPIRE_NEW }"
              add_closing_rsv( rsv )
            end
          end

          @src_infos.each do | src, src_info |
            last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
            last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]
            expire_after = ( src_info[ :dst ] || src_info[ :tun ] ) ? EXPIRE_AFTER : EXPIRE_NEW

            if ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after ) then
              puts "p#{ Process.pid } #{ Time.new } expire src #{ expire_after } #{ src_info[ :id ] } #{ src_info[ :destination_domain ] }"
              add_closing_src( src )

              unless src_info[ :rbuff ].empty? then
                puts "p#{ Process.pid } #{ Time.new } lost rbuff #{ src_info[ :rbuff ].inspect }"
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

          @paused_srcs.each do | src |
            src_info = @src_infos[ src ]
            dst = src_info[ :dst ]

            if dst then
              dst_info = @dst_infos[ dst ]

              if dst_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume direct src #{ src_info[ :destination_domain ] }"
                add_resume_src( src )
              end
            else
              btun = src_info[ :btun ]
              btun_info = @btun_infos[ btun ]

              if btun_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume tunnel src #{ src_info[ :destination_domain ] }"
                add_resume_src( src )
              end
            end
          end

          @paused_dsts.each do | dst |
            dst_info = @dst_infos[ dst ]
            src = dst_info[ :src ]
            src_info = @src_infos[ src ]

            if src_info[ :wbuff ].size < RESUME_BELOW then
              puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain ] }"
              add_resume_dst( dst )
            end
          end

          @paused_btuns.each do | btun |
            btun_info = @btun_infos[ btun ]
            src = btun_info[ :src ]
            src_info = @src_infos[ src ]

            if src_info[ :wbuff ].size < RESUME_BELOW then
              puts "p#{ Process.pid } #{ Time.new } resume btun #{ btun_info[ :domain ] }"
              add_resume_btun( btun )
            end
          end
        end
      end
    end

    ##
    # loop resend ctlmsg
    #
    def loop_resend_ctlmsg( key, ctlmsg )
      Thread.new do
        loop do
          sleep RESEND_INTERVAL

          resend = @ctl_info[ :resends ][ key ]
          break unless resend

          puts "p#{ Process.pid } #{ Time.new } resend #{ ctlmsg.inspect }"
          send_ctlmsg( ctlmsg )
          resend += 1

          if resend >= RESEND_LIMIT then
            @ctl_info[ :resends ].delete( key )
            break
          end

          @ctl_info[ :resends ][ key ] = resend
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
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

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

      # puts "debug a new dst #{ dst.local_address.inspect }"
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
        # puts "debug move src.rbuff to dst.wbuff"
        dst_info[ :wbuff ] << src_info[ :rbuff ]
        add_write( dst )
      end
    end

    ##
    # new a ctl
    #
    def new_a_ctl
      ctl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        ctl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      @ctl = ctl
      add_read( ctl, :ctl )

      @ctl_info = {
        resends: ConcurrentHash.new, # key => count
        atund_addr: nil,             # atund地址，src->dst
        btund_addr: nil,             # btund地址，dst->src
        closing: false,              # 准备关闭
        created_at: Time.new,        # 创建时间
        last_recv_at: nil            # 最近一次收到数据时间
      }

      hello = @custom.hello
      puts "p#{ Process.pid } #{ Time.new } hello i'm #{ hello.inspect }"
      key = [ HELLO ].pack( 'C' )
      add_ctlmsg( key, hello )
    end

    ##
    # new a redir
    #
    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
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
    # new tuns
    #
    def new_tuns( src_id, dst_id )
      src = @srcs[ src_id ]
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :dst_id ]

      # puts "debug new atun and btun"
      atun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

      begin
        atun.connect_nonblock( @ctl_info[ :atund_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect atund #{ e.class }, close atun"
        atun.close
        return
      end

      btun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

      begin
        btun.connect_nonblock( @ctl_info[ :btund_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect btund #{ e.class }, close btun"
        btun.close
        return
      end

      domain = src_info[ :destination_domain ]
      atun_wbuff = [ dst_id ].pack( 'n' )

      until src_info[ :rbuff ].empty? do
        data = src_info[ :rbuff ][ 0, 65535 ]
        data_size = data.bytesize
        # puts "debug move src.rbuff #{ data_size } to atun.wbuff"
        atun_wbuff << pack_a_chunk( data )
        src_info[ :rbuff ] = src_info[ :rbuff ][ data_size..-1 ]
      end

      @atun_infos[ atun ] = {
        src: src,          # 对应src
        domain: domain,    # 目的地
        wbuff: atun_wbuff, # 写前
        closing: false     # 准备关闭
      }

      btun_wbuff = [ dst_id ].pack( 'n' )

      @btun_infos[ btun ] = {
        src: src,          # 对应src
        domain: domain,    # 目的地
        wbuff: btun_wbuff, # 写前
        rbuff: '',         # 暂存当前块没收全的流量
        wait_bytes: 0      # 还差多少字节收全当前块
      }

      src_info[ :dst_id ] = dst_id
      src_info[ :atun ] = atun
      src_info[ :btun ] = btun
      add_read( atun, :atun )
      add_read( btun, :btun )
      add_write( atun )
      add_write( btun )
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
      # puts "debug pack a chunk"
      data = @custom.encode( data )
      "#{ [ data.bytesize ].pack( 'n' ) }#{ data }"
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( data )
      return if @ctl.nil? || @ctl.closed?

      begin
        @ctl.sendmsg( data, 0, @proxyd_addr )
        @ctl_info[ :last_sent_at ] = Time.new
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } sendmsg #{ e.class }"
        close_ctl( @ctl )
      end
    end

    ##
    # set atun closing
    #
    def set_atun_closing( atun )
      return if atun.closed?
      atun_info = @atun_infos[ atun ]
      return if atun_info[ :closing ]
      # puts "debug set atun closing"
      atun_info[ :closing ] = true
      add_write( atun )
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

      if @ctl && !@ctl.closed? && @ctl_info[ :atund_addr ] then
        add_a_new_source( src )
      else
        @pending_srcs << src
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
    # sub http request
    #
    def sub_http_request( data )
      lines = data.split( "\r\n" )

      return [ data, nil ] if lines.empty?

      method, url, proto = lines.first.split( ' ' )

      if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://' then
        domain_port = url.split( '/' )[ 2 ]
        data = data.sub( "http://#{ domain_port }", '' )
        # puts "debug subed #{ data.inspect } #{ domain_port }"
      end

      [ data, domain_port ]
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( 65535 )

      if @ctl_info && @ctl_info[ :closing ] then
        send_ctlmsg( [ CTL_FIN ].pack( 'C' ) )
        close_ctl( @ctl )
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

      if @resume_btuns.any? then
        @resume_btuns.each do | btun |
          add_read( btun )
          @paused_btuns.delete( btun )
        end

        @resume_btuns.clear
      end
    end

    ##
    # read resolv
    #
    def read_resolv( resolv )
      data, addrinfo, rflags, *controls = resolv.recvmsg
      # puts "debug resolv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      new_a_rsv( addrinfo.to_sockaddr, data )
    end

    ##
    # read rsv
    #
    def read_rsv( rsv )
      data, addrinfo, rflags, *controls = rsv.recvmsg
      # puts "debug rsv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"

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
      # puts "debug accept a src #{ addrinfo.ip_unpack.inspect } to #{ dest_ip }:#{ dest_port } #{ src_id }"

      @srcs[ src_id ] = src
      @src_infos[ src ] = {
        id: src_id,                  # id
        proxy_type: :checking,       # :checking / :direct / :tunnel
        destination_domain: dest_ip, # 目的地域名
        destination_port: dest_port, # 目的地端口
        rbuff: '',                   # 读到的流量
        dst: nil,                    # :direct的场合，对应的dst
        ctl: nil,                    # :tunnel的场合，对应的ctl
        atun: nil,                   # :tunnel的场合，对应的atun
        btun: nil,                   # :tunnel的场合，对应的btun
        dst_id: nil,                 # 远端dst id
        wbuff: '',                   # 从dst/btun读到的流量
        created_at: Time.new,        # 创建时间
        last_recv_at: nil,           # 上一次收到新流量（由dst收到，或者由tun收到）的时间
        last_sent_at: nil,           # 上一次发出流量（由dst发出，或者由tun发出）的时间
        closing_write: false         # 准备关闭写
      }

      add_read( src, :src )

      if @ctl.nil? || @ctl.closed? then
        new_a_ctl
      end

      deal_with_destination_ip( src, dest_addrinfo )
    end

    ##
    # read ctl
    #
    def read_ctl( ctl )
      begin
        data, addrinfo, rflags, *controls = ctl.recvmsg
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } recvmsg #{ e.class }"
        close_ctl( ctl )
        return
      end

      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when TUND_PORT then
        return if @ctl_info[ :atund_addr ] || data.size != 5
        atund_port, btund_port = data[ 1, 4 ].unpack( 'nn' )
        puts "p#{ Process.pid } #{ Time.new } got tund port #{ atund_port } #{ btund_port }"
        @ctl_info[ :resends ].delete( [ HELLO ].pack( 'C' ) )
        @ctl_info[ :atund_addr ] = Socket.sockaddr_in( atund_port, @proxyd_host )
        @ctl_info[ :btund_addr ] = Socket.sockaddr_in( btund_port, @proxyd_host )
        @ctl_info[ :last_recv_at ] = Time.new

        if @pending_srcs.any? then
          puts "p#{ Process.pid } #{ Time.new } send pending sources"
          @pending_srcs.each { | src | add_a_new_source( src ) }
          @pending_srcs.clear
        end
      when PAIRED then
        return if @ctl_info[ :atund_addr ].nil? || @ctl_info[ :btund_addr ].nil? || data.size != 11
        src_id, dst_id = data[ 1, 10 ].unpack( 'Q>n' )
        # puts "debug got paired #{ src_id } #{ dst_id }"
        @ctl_info[ :resends ].delete( [ A_NEW_SOURCE, src_id ].pack( 'CQ>' ) )
        @ctl_info[ :last_recv_at ] = Time.new
        new_tuns( src_id, dst_id )
      when UNKNOWN_CTL_ADDR then
        puts "p#{ Process.pid } #{ Time.new } got unknown ctl addr, close ctl"
        close_ctl( ctl )
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

      src_info = @src_infos[ src ]

      begin
        data = src.read_nonblock( 65535 )
      rescue IO::WaitReadable
        print 'r'
        return
      rescue Exception => e
        # puts "debug read src #{ e.class }"
        close_read_src( src )
        dst = src_info[ :dst ]

        if dst then
          set_dst_closing_write( dst )
        else
          atun = src_info[ :atun ]

          if atun then
            set_atun_closing( atun )
          end
        end

        return
      end

      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :checking then
        # puts "debug add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :tunnel then
        atun = src_info[ :atun ]

        if atun then
          add_atun_wbuff( atun, pack_a_chunk( data ) )
        else
          # puts "debug add src.rbuff #{ data.bytesize }"
          add_src_rbuff( src, data )
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          add_dst_wbuff( dst, data )
        else
          # puts "debug add src.rbuff #{ data.bytesize }"
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

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]

      begin
        data = dst.read_nonblock( 65535 )
      rescue IO::WaitReadable
        print 'r'
        return
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_src_closing_write( src )
        return
      end

      # puts "debug read dst #{ data.bytesize }"
      add_src_wbuff( src, data )
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
      src = btun_info[ :src ]

      begin
        data = btun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read btun #{ btun_info[ :im ] } #{ e.class }"
        close_btun( btun )

        if src then
          set_src_closing_write( src )
        end

        return
      end

      until data.empty? do
        rbuff = btun_info[ :rbuff ]
        wait_bytes = btun_info[ :wait_bytes ]

        if wait_bytes > 0 then
          len = wait_bytes
          # puts "debug wait bytes #{ len }"
        else
          if data.bytesize <= 2 then
            # puts "debug unexpect data length #{ data.bytesize }"
            close_btun( btun )
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
          # puts "debug read btun decoded #{ chunk.bytesize }"
          add_src_wbuff( src, chunk )
          btun_info[ :rbuff ] = ''
          btun_info[ :wait_bytes ] = 0
        else
          # 暂存
          # puts "debug add btun.rbuff #{ chunk_size } wait bytes #{ len - chunk_size }"
          btun_info[ :rbuff ] << chunk
          btun_info[ :wait_bytes ] = len - chunk_size
        end

        data = data[ chunk_size..-1 ]
      end
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
        # puts "debug write src #{ e.class }"
        close_write_src( src )

        if dst then
          close_read_dst( dst )
        else
          btun = src_info[ :btun ]

          if btun then
            close_btun( btun )
          end
        end

        return
      end

      # puts "debug write src #{ written }"
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
        # puts "debug write dst #{ e.class }"
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
    # write atun
    #
    def write_atun( atun )
      if atun.closed? then
        puts "p#{ Process.pid } #{ Time.new } write atun but atun closed?"
        return
      end

      atun_info = @atun_infos[ atun ]
      src = atun_info[ :src ]
      data = atun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if atun_info[ :closing ] then
          close_atun( atun )
        else
          @writes.delete( atun )
        end

        return
      end

      # 写入
      begin
        written = atun.write_nonblock( data )
      rescue IO::WaitWritable
        print 'w'
        return
      rescue Exception => e
        # puts "debug write atun #{ e.class }"
        close_atun( atun )
        close_read_src( src )
        return
      end

      # puts "debug write atun #{ written }"
      data = data[ written..-1 ]
      atun_info[ :wbuff ] = data

      unless src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
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
      data = btun_info[ :wbuff ]

      # 写入dst id
      begin
        written = btun.write( data )
      rescue Exception => e
        # puts "debug write btun #{ e.class }"
        src = btun_info[ :src ]
        close_btun( btun )
        add_closing_src( src )
        return
      end

      # puts "debug write btun #{ written }"
      @writes.delete( btun )
    end

  end
end
