module Girl
  class ProxyWorker

    ##
    # initialize
    #
    def initialize( proxy_port, proxyd_host, proxyd_port, directs, remotes, im )
      @proxyd_host = proxyd_host
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @directs = directs
      @remotes = remotes
      @custom = Girl::ProxyCustom.new( im )
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}         # sock => :dotr / :proxy / :src / :dst / :tun / :stream
      @src_infos = {}     # src => {}
      @dst_infos = {}     # dst => {}
      @stream_infos = {}  # stream => {}
      @resolv_caches = {} # domain => [ ip, created_at ]

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_proxy( proxy_port )
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

        @mutex.synchronize do
          # 先读，再写，避免打上关闭标记后读到
          rs.each do | sock |
            case @roles[ sock ]
            when :dotr then
              read_dotr( sock )
            when :proxy then
              read_proxy( sock )
            when :tun then
              read_tun( sock )
            when :src then
              read_src( sock )
            when :dst then
              read_dst( sock )
            when :stream then
              read_stream( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :tun then
              write_tun( sock )
            when :src then
              write_src( sock )
            when :dst then
              write_dst( sock )
            when :stream then
              write_stream( sock )
            end
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
      if @tun && !@tun.closed? && @tun_info[ :tund_addr ] then
        # puts "debug1 send tun fin"
        data = [ 0, TUN_FIN ].pack( 'Q>C' )
        @tun.sendmsg( data, 0, @tun_info[ :tund_addr ] )
      end

      # puts "debug1 exit"
      exit
    end

    private

    ##
    # add ctlmsg
    #
    def add_ctlmsg( data, to_addr = nil )
      unless to_addr then
        to_addr = @tun_info[ :tund_addr ]
      end

      if to_addr then
        @tun_info[ :ctlmsgs ] << [ data, to_addr ]
        add_write( @tun )
      end
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      unless @reads.include?( sock ) then
        @reads << sock

        if role then
          @roles[ sock ] = role
        end
      end
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      return if src.closed?
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      add_write( src )
      src_info[ :last_recv_at ] = Time.new
    end

    ##
    # add src wbuff socks5 conn reply
    #
    def add_src_wbuff_socks5_conn_reply( src )
      # +----+-----+-------+------+----------+----------+
      # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      # +----+-----+-------+------+----------+----------+
      # | 1  |  1  | X'00' |  1   | Variable |    2     |
      # +----+-----+-------+------+----------+----------+
      proxy_ip, proxy_port = @proxy_local_address.ip_unpack
      data = [ [ 5, 0, 0, 1 ].pack( 'C4' ), IPAddr.new( proxy_ip ).hton, [ proxy_port ].pack( 'n' ) ].join
      # puts "debug1 add src wbuff socks5 conn reply #{ data.inspect }"
      add_src_wbuff( src, data )
    end

    ##
    # add write
    #
    def add_write( sock )
      unless @writes.include?( sock ) then
        @writes << sock
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
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      @dst_infos.delete( dst )
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
        @roles.delete( src )
        src_info = del_src_info( src )
      else
        src_info = @src_infos[ src ]
      end

      src_info[ :paused ] = false
      src_info
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
        @roles.delete( dst )
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close read stream
    #
    def close_read_stream( stream )
      return if stream.closed?
      # puts "debug1 close read stream"
      stream.close_read
      @reads.delete( stream )

      if stream.closed? then
        # puts "debug1 delete stream info"
        @roles.delete( stream )
        stream_info = @stream_infos.delete( stream )
      else
        stream_info = @stream_infos[ stream ]
      end

      stream_info
    end

    ##
    # close src
    #
    def close_src( src )
      # puts "debug1 close src"
      close_sock( src )
      del_src_info( src )
    end

    ##
    # close tun
    #
    def close_tun( tun )
      # puts "debug1 close tun"
      close_sock( tun )
      @tun_info[ :srcs ].each{ | _, src | set_src_closing( src ) }
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
        @roles.delete( src )
        src_info = del_src_info( src )
      else
        src_info = @src_infos[ src ]
      end

      src_info
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
        @roles.delete( dst )
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close write stream
    #
    def close_write_stream( stream )
      return if stream.closed?
      # puts "debug1 close write stream"
      stream.close_write
      @writes.delete( stream )

      if stream.closed? then
        # puts "debug1 delete stream info"
        @roles.delete( stream )
        stream_info = @stream_infos.delete( stream )
      else
        stream_info = @stream_infos[ stream ]
      end

      stream_info
    end

    ##
    # deal with destination ip
    #
    def deal_with_destination_ip( src, ip_info )
      src_info = @src_infos[ src ]

      if ( @directs.any? { | direct | direct.include?( ip_info.ip_address ) } ) || ( ( src_info[ :destination_domain ] == @proxyd_host ) && ![ 80, 443 ].include?( src_info[ :destination_port ] ) ) then
        # ip命中直连列表，或者访问远端非80/443端口，直连
        # puts "debug1 #{ ip_info.inspect } hit directs"
        new_a_dst( src, ip_info )
      else
        # 走远端
        # puts "debug1 #{ ip_info.inspect } go tunnel"
        set_src_proxy_type_tunnel( src )
      end
    end

    ##
    # del src info
    #
    def del_src_info( src )
      src_info = @src_infos.delete( src )

      if src_info[ :stream ] && @tun && !@tun.closed? then
        @tun_info[ :srcs ].delete( src_info[ :id ] )
      end

      src_info
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            trigger = false
            now = Time.new

            if @tun && !@tun.closed? then
              last_recv_at = @tun_info[ :last_recv_at ] || @tun_info[ :created_at ]
              last_sent_at = @tun_info[ :last_sent_at ] || @tun_info[ :created_at ]

              if @tun_info[ :srcs ].empty? && ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                puts "p#{ Process.pid } #{ Time.new } expire tun"
                set_tun_closing
                trigger = true
              end
            end

            @src_infos.each do | src, src_info |
              last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
              last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]

              if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                puts "p#{ Process.pid } #{ Time.new } expire src #{ src_info[ :destination_domain ] }"
                set_src_closing( src )
                trigger = true
              end
            end

            next_tick if trigger
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
            trigger = false

            @src_infos.select{ | _, src_info | src_info[ :paused ] }.each do | src, src_info |
              dst = src_info[ :dst ]

              if dst then
                dst_info = @dst_infos[ dst ]

                if dst_info[ :wbuff ].size < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } dst.wbuff below #{ RESUME_BELOW }, resume src #{ src_info[ :destination_domain ] }"
                  resume_src( src )
                  trigger = true
                end
              else
                stream = src_info[ :stream ]
                stream_info = @stream_infos[ stream ]

                if stream_info[ :wbuff ].size < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } stream.wbuff below #{ RESUME_BELOW }, resume src #{ src_info[ :destination_domain ] }"
                  resume_src( src )
                  trigger = true
                end
              end
            end

            next_tick if trigger
          end
        end
      end
    end

    ##
    # loop send a new source
    #
    def loop_send_a_new_source( src )
      src_info = @src_infos[ src ]

      if src_info then
        destination_domain = src_info[ :destination_domain ]
        destination_port = src_info[ :destination_port ]
        domain_port = [ destination_domain, destination_port ].join( ':' )
        data = [ [ 0, A_NEW_SOURCE, src_info[ :id ] ].pack( 'Q>CQ>' ), @custom.encode( domain_port ) ].join

        Thread.new do
          SEND_HELLO_COUNT.times do | i |
            if @tun.nil? || @tun.closed? || src.closed? || src_info[ :stream ] then
              # puts "debug1 break loop send a new source #{ src_info[ :dst_port ] }"
              break
            end

            @mutex.synchronize do
              if i >= 1 then
                puts "p#{ Process.pid } #{ Time.new } resend a new source #{ domain_port } #{ i }"
              end

              add_ctlmsg( data )
              next_tick
            end

            sleep 1
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( src, ip_info )
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
        puts "p#{ Process.pid } #{ Time.new } dst connect destination #{ e.class }, close src"
        set_src_closing( src )
        return
      end

      # puts "debug1 a new dst #{ dst.local_address.inspect }"
      local_port = dst.local_address.ip_port
      dst_info = {
        local_port: local_port, # 本地端口
        src: src,               # 对应src
        domain: domain,         # 域名
        wbuff: '',              # 写前，从src读到的流量
        closing: false,         # 准备关闭
        closing_read: false,    # 准备关闭读
        closing_write: false    # 准备关闭写
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          # puts "debug1 add src.wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        elsif src_info[ :rbuff ] then
          # puts "debug1 move src.rbuff to dst.wbuff"
          dst_info[ :wbuff ] << src_info[ :rbuff ]
          add_write( dst )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_src_wbuff_socks5_conn_reply( src )
      end
    end

    ##
    # new a stream
    #
    def new_a_stream( src_id, dst_id )
      src = @tun_info[ :srcs ][ src_id ]
      return if src.nil? || src.closed?

      src_info = @src_infos[ src ]
      return if src_info[ :dst_id ]

      if dst_id == 0 then
        puts "p#{ Process.pid } #{ Time.new } remote dst already closed"
        set_src_closing( src )
        return
      end

      stream = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      stream.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 ) if RUBY_PLATFORM.include?( 'linux' )

      begin
        stream.connect_nonblock( @tun_info[ :tcpd_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect tcpd #{ e.class }"
        return
      end

      # puts "debug1 set stream.wbuff #{ dst_id }"
      data = [ dst_id ].pack( 'n' )

      unless src_info[ :rbuff ].empty? then
        # puts "debug1 encode and move src.rbuff to stream.wbuff"
        data << @custom.encode( src_info[ :rbuff ] )
      end

      @stream_infos[ stream ] = {
        src: src,   # 对应src
        wbuff: data # 写前，写往远端streamd
      }

      src_info[ :dst_id ] = dst_id
      src_info[ :stream ] = stream
      add_read( stream, :stream )
      add_write( stream )

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          # puts "debug1 add src.wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_src_wbuff_socks5_conn_reply( src )
      end
    end

    ##
    # new a proxy
    #
    def new_a_proxy( proxy_port )
      proxy = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxy.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        proxy.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        proxy.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      proxy.bind( Socket.sockaddr_in( proxy_port, '0.0.0.0' ) )
      proxy.listen( 127 )
      puts "p#{ Process.pid } #{ Time.new } proxy listen on #{ proxy_port }"
      add_read( proxy, :proxy )
      @proxy_local_address = proxy.local_address
    end

    ##
    # new a tun
    #
    def new_a_tun
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      port = tun.local_address.ip_port
      tun_info = {
        port: port,           # 端口
        pending_sources: [],  # 还没配上tund，暂存的src
        ctlmsgs: [],          # [ ctlmsg, to_addr ]
        tund_addr: nil,       # tund地址
        tcpd_addr: nil,       # tcpd地址
        srcs: {},             # src_id => src
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间
        last_sent_at: nil,    # 上一次发出流量的时间
        closing: false        # 是否准备关闭
      }

      @tun = tun
      @tun_info = tun_info

      add_read( tun, :tun )
      data = @custom.hello

      Thread.new do
        SEND_HELLO_COUNT.times do | i |
          if @tun.nil? || @tun.closed? || @tun_info[ :tund_addr ] then
            # puts "debug1 break loop send hello"
            break
          end

          @mutex.synchronize do
            msg = i >= 1 ? "resend hello #{ i }" : "hello i'm tun"
            puts "p#{ Process.pid } #{ Time.new } #{ msg }"
            # puts "debug1 #{ data.inspect }"

            add_ctlmsg( data, @proxyd_addr )
            next_tick
          end

          sleep 1
        end
      end
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
    def resolve_domain( src, domain )
      if @remotes.any? { | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) } then
        # puts "debug1 #{ domain } hit remotes"
        set_src_proxy_type_tunnel( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip_info, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug1 #{ domain } hit resolv cache #{ ip_info.inspect }"
          deal_with_destination_ip( src, ip_info )
          return
        end

        # puts "debug1 expire #{ domain } resolv cache"
        @resolv_caches.delete( domain )
      end

      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :checking

      Thread.new do
        begin
          ip_info = Addrinfo.ip( domain )
        rescue Exception => e
          puts "p#{ Process.pid } #{ Time.new } resolv #{ domain } #{ e.class }"
        end

        @mutex.synchronize do
          if ip_info then
            @resolv_caches[ domain ] = [ ip_info, Time.new ]

            unless src.closed? then
              puts "p#{ Process.pid } #{ Time.new } resolved #{ domain } #{ ip_info.ip_address }"
              deal_with_destination_ip( src, ip_info )
            end
          else
            set_src_closing( src )
          end

          next_tick
        end
      end
    end

    ##
    # resume src
    #
    def resume_src( src )
      src_info = @src_infos[ src ]
      src_info[ :paused ] = false
      add_read( src )
    end

    ##
    # set dst closing
    #
    def set_dst_closing( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :closing ] = true
      @reads.delete( dst )
      add_write( dst )
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set src is closing
    #
    def set_src_closing( src )
      return if src.closed?
      @reads.delete( src )
      src_info = @src_infos[ src ]
      src_info[ :closing ] = true
      add_write( src )
    end

    ##
    # set src closing write
    #
    def set_src_closing_write( src )
      return if src.closed?
      src_info = @src_infos[ src ]
      src_info[ :closing_write ] = true
      add_write( src )
    end

    ##
    # set src proxy type tunnel
    #
    def set_src_proxy_type_tunnel( src )
      if @tun.nil? || @tun.closed? then
        new_a_tun
      end

      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :tunnel
      src_id = src_info[ :id ]
      @tun_info[ :srcs ][ src_id ] = src

      if @tun_info[ :tund_addr ] then
        loop_send_a_new_source( src )
      else
        @tun_info[ :pending_sources ] << src
      end
    end

    ##
    # set stream closing
    #
    def set_stream_closing( stream )
      return if stream.closed?
      stream_info = @stream_infos[ stream ]
      stream_info[ :closing ] = true
      @reads.delete( stream )
      add_write( stream )
    end

    ##
    # set stream closing write
    #
    def set_stream_closing_write( stream )
      return if stream.closed?
      stream_info = @stream_infos[ stream ]
      stream_info[ :closing_write ] = true
      add_write( stream )
    end

    ##
    # set tun is closing
    #
    def set_tun_closing
      return if @tun.closed?
      @tun_info[ :closing ] = true
      @reads.delete( @tun )
      add_write( @tun )
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
      dotr.read( 1 )
    end

    ##
    # read proxy
    #
    def read_proxy( proxy )
      begin
        src, addrinfo = proxy.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      end

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug1 accept a src #{ addrinfo.inspect } #{ src_id }"

      @src_infos[ src ] = {
        id: src_id,              # id
        proxy_proto: :uncheck,   # :uncheck / :http / :socks5
        proxy_type: :uncheck,    # :uncheck / :checking / :direct / :tunnel / :negotiation
        destination_domain: nil, # 目的地域名
        destination_port: nil,   # 目的地端口
        is_connect: true,        # 代理协议是http的场合，是否是CONNECT
        rbuff: '',               # 读到的流量
        dst: nil,                # :direct的场合，对应的dst
        stream: nil,             # :tunnel的场合，对应的stream
        dst_id: nil,             # 远端dst id
        wbuff: '',               # 从dst/stream读到的流量
        created_at: Time.new,    # 创建时间
        last_recv_at: nil,       # 上一次收到新流量（由dst收到，或者由stream收到）的时间
        last_sent_at: nil,       # 上一次发出流量（由dst发出，或者由stream发出）的时间
        paused: false,           # 是否已暂停
        closing: false,          # 准备关闭
        closing_read: false,     # 准备关闭读
        closing_write: false     # 准备关闭写
      }

      add_read( src, :src )
    end

    ##
    # read tun
    #
    def read_tun( tun )
      begin
        data, addrinfo, rflags, *controls = tun.recvmsg_nonblock
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      end

      from_addr = addrinfo.to_sockaddr
      @tun_info[ :last_recv_at ] = Time.new
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first
      return if pack_id != 0

      ctl_num = data[ 8 ].unpack( 'C' ).first

      case ctl_num
      when TUND_PORT then
        return if ( from_addr != @proxyd_addr ) || @tun_info[ :tund_addr ]

        tund_port, tcpd_port = data[ 9, 4 ].unpack( 'nn' )

        puts "p#{ Process.pid } #{ Time.new } got tund port #{ tund_port }, #{ tcpd_port }"
        @tun_info[ :tund_addr ] = Socket.sockaddr_in( tund_port, @proxyd_host )
        @tun_info[ :tcpd_addr ] = Socket.sockaddr_in( tcpd_port, @proxyd_host )

        if @tun_info[ :pending_sources ].any? then
          puts "p#{ Process.pid } #{ Time.new } send pending sources"

          @tun_info[ :pending_sources ].each do | src |
            loop_send_a_new_source( src )
          end

          @tun_info[ :pending_sources ].clear
        end
      when PAIRED then
        return if from_addr != @tun_info[ :tund_addr ]

        src_id, dst_id = data[ 9, 10 ].unpack( 'Q>n' )

        # puts "debug1 got paired #{ src_id } #{ dst_id }"
        new_a_stream( src_id, dst_id )
      when TUND_FIN then
        return if from_addr != @tun_info[ :tund_addr ]

        puts "p#{ Process.pid } #{ Time.new } recv tund fin"
        set_tun_closing
      when IP_CHANGED then
        return if from_addr != @tun_info[ :tund_addr ]

        puts "p#{ Process.pid } #{ Time.new } recv ip changed"
        set_tun_closing
      end
    end

    ##
    # read src
    #
    def read_src( src )
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
          stream = src_info[ :stream ]
          set_stream_closing_write( stream ) if stream
        end

        return
      end

      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0, 7 ] == 'CONNECT' then
          # puts "debug1 CONNECT"
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port then
            puts "p#{ Process.pid } #{ Time.new } CONNECT miss domain"
            set_src_closing( src )
            return
          end
        elsif data[ 0 ].unpack( 'C' ).first == 5 then
          # puts "debug1 socks5 #{ data.inspect }"

          # https://tools.ietf.org/html/rfc1928
          #
          # +----+----------+----------+
          # |VER | NMETHODS | METHODS  |
          # +----+----------+----------+
          # | 1  |    1     | 1 to 255 |
          # +----+----------+----------+
          nmethods = data[ 1 ].unpack( 'C' ).first
          methods = data[ 2, nmethods ].unpack( 'C*' )

          unless methods.include?( 0 ) then
            puts "p#{ Process.pid } #{ Time.new } miss method 00"
            set_src_closing( src )
            return
          end

          # +----+--------+
          # |VER | METHOD |
          # +----+--------+
          # | 1  |   1    |
          # +----+--------+
          data2 = [ 5, 0 ].pack( 'CC' )
          add_src_wbuff( src, data2 )
          src_info[ :proxy_proto ] = :socks5
          src_info[ :proxy_type ] = :negotiation
          return
        else
          # puts "debug1 not CONNECT #{ data.inspect }"
          host_line = data.split( "\r\n" ).find { | _line | _line[ 0, 6 ] == 'Host: ' }

          unless host_line then
            # puts "debug1 not found host line"
            set_src_closing( src )
            return
          end

          data, domain_port = sub_http_request( data )

          unless domain_port then
            # puts "debug1 not HTTP"
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
              puts "p#{ Process.pid } #{ Time.new } Host line miss domain"
              set_src_closing( src )
              return
            end
          end

          src_info[ :is_connect ] = false
          src_info[ :rbuff ] << data
        end

        domain, port = domain_port.split( ':' )
        port = port ? port.to_i : 80

        src_info[ :proxy_proto ] = :http
        src_info[ :destination_domain ] = domain
        src_info[ :destination_port ] = port

        resolve_domain( src, domain )
      when :checking then
        # puts "debug1 add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :negotiation then
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        # puts "debug1 negotiation #{ data.inspect }"
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1 then
          # puts "debug1 socks5 CONNECT"

          if atyp == 1 then
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )
            destination_addr = Socket.sockaddr_in( destination_port, destination_host )
            destination_addrinfo = Addrinfo.new( destination_addr )
            destination_ip = destination_addrinfo.ip_address
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            # puts "debug1 IP V4 address #{ destination_addrinfo.inspect }"
            deal_with_destination_ip( src, destination_addrinfo )
          elsif atyp == 3 then
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize then
              domain = data[ 5, domain_len ]
              port = data[ ( 5 + domain_len ), 2 ].unpack( 'n' ).first
              src_info[ :destination_domain ] = domain
              src_info[ :destination_port ] = port
              # puts "debug1 DOMAINNAME #{ domain } #{ port }"
              resolve_domain( src, domain )
            end
          end
        else
          puts "p#{ Process.pid } #{ Time.new } socks5 cmd #{ cmd } not implement"
        end
      when :tunnel then
        stream = src_info[ :stream ]

        if stream then
          unless stream.closed? then
            unless src_info[ :is_connect ] then
              data, _ = sub_http_request( data )
            end

            stream_info = @stream_infos[ stream ]
            data = @custom.encode( data )
            # puts "debug2 add stream.wbuff encoded #{ data.bytesize }"
            stream_info[ :wbuff ] << data
            add_write( stream )

            if stream_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
              puts "p#{ Process.pid } #{ Time.new } pause tunnel src #{ src_info[ :id ] } #{ src_info[ :destination_domain ] }"
              src_info[ :paused ] = true
              @reads.delete( src )
            end
          end
        else
          # puts "debug1 stream not ready, save data to src.rbuff"
          src_info[ :rbuff ] << data

          if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
            # puts "debug1 tunnel src.rbuff full"
            set_src_closing( src )
          end
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          unless dst.closed? then
            unless src_info[ :is_connect ] then
              data, _ = sub_http_request( data )
            end

            dst_info = @dst_infos[ dst ]
            # puts "debug2 add dst.wbuff #{ data.bytesize }"
            dst_info[ :wbuff ] << data
            add_write( dst )

            if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
              puts "p#{ Process.pid } #{ Time.new } pause direct src #{ src_info[ :id ] } #{ src_info[ :destination_domain ] }"
              src_info[ :paused ] = true
              @reads.delete( src )
            end
          end
        else
          # puts "debug1 dst not ready, save data to src.rbuff"
          src_info[ :rbuff ] << data

          if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
            # puts "debug1 direct src.rbuff full"
            set_src_closing( src )
          end
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
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
    # read stream
    #
    def read_stream( stream )
      begin
        data = stream.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read stream #{ e.class }"
        stream_info = close_read_stream( stream )
        src = stream_info[ :src ]
        set_src_closing_write( src )
        return
      end

      stream_info = @stream_infos[ stream ]
      src = stream_info[ :src ]
      data = @custom.decode( data )
      # puts "debug2 add src.wbuff decoded #{ data.bytesize }"
      add_src_wbuff( src, data )
    end

    ##
    # write tun
    #
    def write_tun( tun )
      # 处理关闭
      if @tun_info[ :closing ] then
        close_tun( tun )
        return
      end

      now = Time.new

      # 发ctlmsg
      while @tun_info[ :ctlmsgs ].any? do
        data, to_addr = @tun_info[ :ctlmsgs ].first

        begin
          @tun.sendmsg_nonblock( data, 0, to_addr )
        rescue IO::WaitWritable, Errno::EINTR
          puts "p#{ Process.pid } #{ Time.new } wait send ctlmsg, left #{ @tun_info[ :ctlmsgs ].size }"
          @tun_info[ :last_sent_at ] = now
          return
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
          puts "p#{ Process.pid } #{ Time.new } sendmsg #{ e.class }, close tun"
          close_tun( tun )
          return
        end

        @tun_info[ :ctlmsgs ].shift
      end

      @tun_info[ :last_sent_at ] = now
      @writes.delete( tun )
    end

    ##
    # write src
    #
    def write_src( src )
      return if src.closed?
      src_info = @src_infos[ src ]
      dst = src_info[ :dst ]

      # 处理关闭
      if src_info[ :closing ] then
        close_src( src )

        if dst then
          close_read_dst( dst )
          set_dst_closing_write( dst )
        else
          stream = src_info[ :stream ]

          if stream then
            close_read_stream( stream )
            set_stream_closing_write( stream )
          end
        end

        return
      end

      # 处理wbuff
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
          stream = src_info[ :stream ]
          close_read_stream( stream ) if stream
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
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]

      # 处理关闭
      if dst_info[ :closing ] then
        close_dst( dst )

        if src then
          close_read_src( src )
          set_src_closing_write( src )
        end

        return
      end

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
    # write stream
    #
    def write_stream( stream )
      return if stream.closed?
      stream_info = @stream_infos[ stream ]
      src = stream_info[ :src ]

      # 处理关闭
      if stream_info[ :closing ] then
        close_stream( stream )
        close_read_src( src )
        set_src_closing_write( src )
        return
      end

      data = stream_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if stream_info[ :closing_write ] then
          close_write_stream( stream )
        else
          @writes.delete( stream )
        end

        return
      end

      # 写入
      begin
        written = stream.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write stream #{ e.class }"
        close_write_stream( stream )
        close_read_src( src )
        return
      end

      # puts "debug2 written stream #{ written }"
      data = data[ written..-1 ]
      stream_info[ :wbuff ] = data

      unless src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
