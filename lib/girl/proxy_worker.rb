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
      @roles = {}         # sock => :dotr / :proxy / :src / :dst / :tun
      @src_infos = {}     # src => {}
      @dst_infos = {}     # dst => {}
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
      loop_check_status

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
            when :src then
              write_src( sock )
            when :dst then
              write_dst( sock )
            when :tun then
              write_tun( sock )
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
    # send miss or continue
    #
    def send_miss_or_continue( dst_id, biggest_dst_pack_id )
      now = Time.new
      src_id = @tun_info[ :src_ids ][ dst_id ]

      if src_id then
        src = @tun_info[ :srcs ][ src_id ]

        if src then
          src_info = @src_infos[ src ]
          continue_recv_pack_id = src_info[ :continue_recv_pack_id ]

          if src_info[ :continue_recv_pack_id ] < biggest_dst_pack_id then
            # 有跳号包，发miss（single miss和range miss）。
            singles = []
            ranges = []
            begin_miss_pack_id = continue_recv_pack_id + 1

            src_info[ :pieces ].keys.sort.each do | pack_id |
              if begin_miss_pack_id < pack_id then
                end_miss_pack_id = pack_id - 1

                if begin_miss_pack_id == end_miss_pack_id then
                  singles << begin_miss_pack_id
                else
                  # ranges << [ begin_miss_pack_id, end_miss_pack_id ]
                  singles += ( begin_miss_pack_id..end_miss_pack_id ).to_a
                end
              end

              begin_miss_pack_id = pack_id + 1
            end

            if begin_miss_pack_id <= biggest_dst_pack_id
              # ranges << [ begin_miss_pack_id, biggest_dst_pack_id ]
              singles += ( begin_miss_pack_id..biggest_dst_pack_id ).to_a
            end

            if singles.any? then
              # puts "debug1 #{ now } single miss #{ singles.size } #{ singles[ 0, 10 ].inspect }"
              # idx = 0
              #
              # while idx < singles.size do
              #   data = [ 0, SINGLE_MISS, src_info[ :dst_id ], *( singles[ idx, SINGLE_MISS_LIMIT ] ) ].pack( 'Q>CnQ>*' )
              #   add_ctlmsg( data )
              #   idx += SINGLE_MISS_LIMIT
              # end

              data = [ 0, SINGLE_MISS, src_info[ :dst_id ], *( singles[ 0, SINGLE_MISS_LIMIT ] ) ].pack( 'Q>CnQ>*' )
              add_ctlmsg( data )
            end

            # if ranges.any? then
            #   # puts "debug1 #{ now } range miss #{ ranges.size } #{ ranges[ 0, 10 ].inspect }"
            #   idx = 0
            #
            #   while idx < ranges.size do
            #     data = [ 0, RANGE_MISS, src_info[ :dst_id ], *( ranges[ idx, RANGE_MISS_LIMIT ].flatten ) ].pack( 'Q>CnQ>*' )
            #     add_ctlmsg( data )
            #     idx += RANGE_MISS_LIMIT
            #   end
            # end
          end
        end
      end

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

              if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                puts "p#{ Process.pid } #{ Time.new } expire tun"
                set_tun_is_closing
                trigger = true
              end
            end

            @src_infos.each do | src, src_info |
              last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
              last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]

              if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                if src.closed? then
                  puts "p#{ Process.pid } #{ Time.new } expire src ext #{ src_info[ :destination_domain ] }"
                  del_src_ext( src )
                else
                  puts "p#{ Process.pid } #{ Time.new } expire src #{ src_info[ :destination_domain ] }"
                  set_src_is_closing( src )
                  trigger = true
                end
              end
            end

            if trigger then
              next_tick
            end
          end
        end
      end
    end

    ##
    # loop check status
    #
    def loop_check_status
      Thread.new do
        loop do
          sleep CHECK_STATUS_INTERVAL

          @mutex.synchronize do
            if @tun && !@tun.closed? && @tun_info[ :tund_addr ] then
              now = Time.new

              @tun_info[ :srcs ].each do | _, src |
                src_info = @src_infos[ src ]

                if src_info && src_info[ :dst_id ] then
                  if src_info[ :last_recv_at ] && ( now - src_info[ :last_recv_at ] < 5 ) then
                    data = [ 0, IS_RESEND_READY, src_info[ :dst_id ] ].pack( 'Q>Cn' )
                    add_ctlmsg( data )
                  end

                  # 恢复读
                  if !src_info[ :closed_read ] && src_info[ :paused ] && ( src_info[ :wafters ].size < RESUME_BELOW ) then
                    puts "p#{ Process.pid } #{ Time.new } resume src #{ src_info[ :destination_domain ] }"
                    add_read( src )
                    src_info[ :paused ] = false
                  end
                end
              end

              next_tick
            end
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
            if @tun.nil? || @tun.closed? || src.closed? || src_info[ :dst_id ] then
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
    # resolve domain
    #
    def resolve_domain( src, domain )
      if @remotes.any? { | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) } then
        # puts "debug1 #{ domain } hit remotes"
        new_a_src_ext( src )
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

            unless src.closed?
              puts "p#{ Process.pid } #{ Time.new } resolved #{ domain } #{ ip_info.ip_address }"
              deal_with_destination_ip( src, ip_info )
            end
          else
            set_src_is_closing( src ) unless src.closed?
          end

          next_tick
        end
      end
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
        new_a_src_ext( src )
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
      proxy.listen( 511 )
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
        port: port,             # 端口
        pending_sources: [],    # 还没配上tund，暂存的src
        ctlmsgs: [],            # [ ctlmsg, to_addr ]
        resend_newers: {},      # 尾巴流量重传队列 src_id => newer_pack_ids
        resend_singles: {},     # 单个重传队列 src_id => single_miss_pack_ids
        resend_ranges: {},      # 区间重传队列 src_id => range_miss_pack_ids
        event_srcs: [],         # rbuff不为空，或者准备关闭的src
        tund_addr: nil,         # tund地址
        srcs: {},               # src_id => src
        src_ids: {},            # dst_id => src_id
        created_at: Time.new,   # 创建时间
        last_recv_at: nil,      # 上一次收到流量的时间
        last_sent_at: nil,      # 上一次发出流量的时间
        is_closing: false       # 是否准备关闭
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
    # new a dst
    #
    def new_a_dst( src, ip_info )
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      destination_addr = Socket.sockaddr_in( src_info[ :destination_port ], ip_info.ip_address )
      dst = Socket.new( ip_info.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dst connect destination #{ e.class }, close src"
        set_src_is_closing( src )
        return
      end

      # puts "debug1 a new dst #{ dst.local_address.inspect }"
      local_port = dst.local_address.ip_port
      @dst_infos[ dst ] = {
        local_port: local_port, # 本地端口
        src: src,               # 对应src
        domain: domain,         # 域名
        closed_read: false,     # 是否已关读
        closed_write: false,    # 是否已关写
        is_closing: false       # 是否准备关闭
      }

      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          # puts "debug1 add src wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        elsif src_info[ :rbuff ]
          # puts "debug1 relay rbuff after dst ready"
          add_write( dst )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_src_wbuff_socks5_conn_reply( src )
      end
    end

    ##
    # new a src ext
    #
    def new_a_src_ext( src )
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
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      add_write( src )
      src_info[ :last_recv_at ] = Time.new
    end

    ##
    # add ctlmsg fin1
    #
    def add_ctlmsg_fin1( src_info )
      data = [ 0, FIN1, src_info[ :id ], src_info[ :biggest_pack_id ] ].pack( 'Q>CQ>Q>' )
      add_ctlmsg( data )
    end

    ##
    # add ctlmsg fin2
    #
    def add_ctlmsg_fin2( src_info )
      data = [ 0, FIN2, src_info[ :id ] ].pack( 'Q>CQ>' )
      add_ctlmsg( data )
    end

    ##
    # add ctlmsg
    #
    def add_ctlmsg( data, to_addr = nil )
      unless to_addr then
        to_addr = @tun_info[ :tund_addr ]
      end

      if to_addr
        @tun_info[ :ctlmsgs ] << [ data, to_addr ]
        add_write( @tun )
      end
    end

    ##
    # add event src
    #
    def add_event_src( src )
      unless @tun_info[ :event_srcs ].include?( src ) then
        @tun_info[ :event_srcs ] << src
        add_write( @tun )
      end
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      unless @reads.include?( sock ) then
        @reads << sock

        if role
          @roles[ sock ] = role
        end
      end
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
    # set src is closing
    #
    def set_src_is_closing( src )
      @reads.delete( src )
      src_info = @src_infos[ src ]
      src_info[ :is_closing ] = true
      add_write( src )
    end

    ##
    # set tun is closing
    #
    def set_tun_is_closing
      @tun_info[ :is_closing ] = true
      @reads.delete( @tun )
      add_write( @tun )
    end

    ##
    # send data
    #
    def send_data( data, to_addr = nil )
      unless to_addr then
        to_addr = @tun_info[ :tund_addr ]
      end

      begin
        written = @tun.sendmsg_nonblock( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        print '.'
        return :wait
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        puts "#{ Time.new } sendmsg #{ e.class }, close tun"
        return :fatal
      end

      written
    end

    ##
    # del src ext
    #
    def del_src_ext( src )
      src_info = @src_infos.delete( src )

      if src_info && @tun && !@tun.closed? && @tun_info then
        if src_info[ :dst_id ] then
          @tun_info[ :src_ids ].delete( src_info[ :dst_id ] )
        end

        @tun_info[ :srcs ].delete( src_info[ :id ] )
      end
    end

    ##
    # close src
    #
    def close_src( src )
      # puts "debug1 close src"
      close_sock( src )
      src_info = @src_infos[ src ]
      dst = src_info[ :dst ]

      if dst then
        # puts "debug1 主动关src -> src.dst？ -> 主动关dst"
        close_dst( dst ) unless dst.closed?
      elsif src_info[ :dst_id ] then
        if @tun && !@tun.closed? then
          # puts "debug1 主动关src -> src.dst_id？ -> 发fin1和fin2"
          add_ctlmsg_fin1( src_info )
          add_ctlmsg_fin2( src_info )
          del_src_ext( src )
        end
      end
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      src = dst_info[ :src ]
      close_src( src ) unless src.closed?
    end

    ##
    # close tun
    #
    def close_tun( tun )
      # puts "debug1 close tun"
      close_sock( tun )
      @tun_info[ :srcs ].each{ | _, src | close_src( src ) unless src.closed? }
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
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
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
        return
      end

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug1 accept a src #{ addrinfo.inspect } #{ src_id }"

      @src_infos[ src ] = {
        id: src_id,               # id
        proxy_proto: :uncheck,    # :uncheck / :http / :socks5
        proxy_type: :uncheck,     # :uncheck / :checking / :direct / :tunnel / :negotiation
        destination_domain: nil,  # 目的地域名
        destination_port: nil,    # 目的地端口
        is_connect: true,         # 代理协议是http的场合，是否是CONNECT
        rbuff: '',                # 读到的流量
        biggest_pack_id: 0,       # 最大包号码
        wbuff: '',                # 从dst/tun读到的流量
        dst: nil,                 # :direct的场合，对应的dst
        dst_id: nil,              # 远端dst id
        continue_recv_pack_id: 0, # 收到的连续的最后一个包号
        pieces: {},               # 跳号包 dst_pack_id => data
        fin1_dst_pack_id: nil,    # 已关闭读的远端dst的最终包号码
        dst_fin2: false,          # 远端dst是否已关闭写
        wafters: {},              # 写后 pack_id => data
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到新流量（由dst收到，或者由tun收到）的时间
        last_sent_at: nil,        # 上一次发出流量（由dst发出，或者由tun发出）的时间
        paused: false,            # 是否已暂停
        closed_read: false,       # 是否已关读
        closed_write: false,      # 是否已关写
        is_closing: false         # 是否准备关闭，为了避免closed stream，一律到下一轮择，只择@writes，择到关闭
      }

      add_read( src, :src )
    end

    ##
    # read src
    #
    def read_src( src )
      begin
        data = src.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 read src #{ e.class }"
        src.close_read
        src_info = @src_infos[ src ]
        src_info[ :closed_read ] = true
        @reads.delete( src )

        if src_info[ :rbuff ].empty? then
          dst = src_info[ :dst ]

          if dst then
            dst.close_write
            dst_info = @dst_infos[ dst ]
            dst_info[ :closed_write ] = true
            @writes.delete( dst )

            if src.closed? then
              # puts "debug1 读src -> 读到error -> 关src读 -> rbuff空？ -> src.dst？ -> 关dst写 -> src已双向关？ -> 删src.info"
              @roles.delete( src )
              @src_infos.delete( src )
            end

            if dst.closed? then
              # puts "debug1 读src -> 读到error -> 关src读 -> rbuff空？ -> src.dst？ -> 关dst写 -> dst已双向关且src.wbuff空？ -> 删dst.info"
              @roles.delete( dst )
              @dst_infos.delete( dst )
            end
          elsif src_info[ :dst_id ] then
            # puts "debug1 读src -> 读到error -> 关src读 -> rbuff空？ -> src.dst_id？ -> 发fin1"
            add_ctlmsg_fin1( src_info )
          end
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
            set_src_is_closing( src )
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
            set_src_is_closing( src )
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
            set_src_is_closing( src )
            return
          end

          data, domain_port = sub_http_request( data )

          unless domain_port then
            # puts "debug1 not HTTP"
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
              puts "p#{ Process.pid } #{ Time.new } Host line miss domain"
              set_src_is_closing( src )
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
        if src_info[ :dst_id ] then
          unless src_info[ :is_connect ] then
            data, _ = sub_http_request( data )
          end

          src_info[ :rbuff ] << data
          add_event_src( src )
        else
          # puts "debug1 remote dst not ready, save data to src rbuff"
          src_info[ :rbuff ] << data
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          unless src_info[ :is_connect ] then
            data, _ = sub_http_request( data )
          end

          src_info[ :rbuff ] << data
          add_write( dst )
        else
          # puts "debug1 dst not ready, save data to src rbuff"
          src_info[ :rbuff ] << data
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
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        dst.close_read
        dst_info = @dst_infos[ dst ]
        dst_info[ :closed_read ] = true
        @reads.delete( dst )
        src = dst_info[ :src ]
        src_info = @src_infos[ src ]

        if src_info[ :wbuff ].empty? then
          src.close_write
          src_info[ :closed_write ] = true
          @writes.delete( src )

          if dst.closed? then
            # puts "debug1 读dst -> 读到error -> 关dst读 -> dst.src.wbuff空？ -> 关src写 -> dst已双向关？ -> 删dst.info"
            @roles.delete( dst )
            @dst_infos.delete( dst )
          end

          if src.closed? then
            # puts "debug1 读dst -> 读到error -> 关dst读 -> dst.src.wbuff空？ -> 关src写 -> src已双向关？ -> 删src.info"
            @roles.delete( src )
            @src_infos.delete( src )
          end
        end

        return
      end

      dst_info = @dst_infos[ dst ]
      add_src_wbuff( dst_info[ :src ], data )
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
      now = Time.new
      @tun_info[ :last_recv_at ] = now
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if pack_id == 0 then
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when TUND_PORT then
          return if ( from_addr != @proxyd_addr ) || @tun_info[ :tund_addr ]

          tund_port = data[ 9, 2 ].unpack( 'n' ).first

          puts "p#{ Process.pid } #{ Time.new } got tund port #{ tund_port }"
          tund_addr = Socket.sockaddr_in( tund_port, @proxyd_host )
          @tun_info[ :tund_addr ] = tund_addr

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

          src = @tun_info[ :srcs ][ src_id ]
          return if src.nil? || src.closed?

          src_info = @src_infos[ src ]
          return if src_info[ :dst_id ]

          if dst_id == 0 then
            set_src_is_closing( src )
            return
          end

          src_info[ :dst_id ] = dst_id
          @tun_info[ :src_ids ][ dst_id ] = src_id

          if src_info[ :proxy_proto ] == :http then
            if src_info[ :is_connect ] then
              # puts "debug1 add src wbuff http ok"
              add_src_wbuff( src, HTTP_OK )
            else
              # puts "debug1 add event src"
              add_event_src( src )
            end
          elsif src_info[ :proxy_proto ] == :socks5 then
            add_src_wbuff_socks5_conn_reply( src )
          end
        when IS_RESEND_READY then
          if @tun_info[ :resend_newers ].empty? && @tun_info[ :resend_singles ].empty? && @tun_info[ :resend_ranges ].empty? then
            src_id = data[ 9, 8 ].unpack( 'Q>' ).first
            return unless src_id

            src = @tun_info[ :srcs ][ src_id ]
            return unless src

            src_info = @src_infos[ src ]
            data2 = [ 0, RESEND_READY, src_id, src_info[ :biggest_pack_id ] ].pack( 'Q>CQ>Q>' )
            add_ctlmsg( data2 )
          end
        when RESEND_READY then
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id, biggest_dst_pack_id = data[ 9, 10 ].unpack( 'nQ>' )
          return if dst_id.nil? || biggest_dst_pack_id.nil?

          send_miss_or_continue( dst_id, biggest_dst_pack_id )
        when SINGLE_MISS then
          return if from_addr != @tun_info[ :tund_addr ]

          src_id, *miss_pack_ids = data[ 9..-1 ].unpack( 'Q>Q>*' )

          return if miss_pack_ids.empty?

          # puts "debug2 got single miss #{ miss_pack_ids[ 0, 100 ].inspect }"

          if @tun_info[ :resend_singles ].include?( src_id ) then
            @tun_info[ :resend_singles ][ src_id ] = ( @tun_info[ :resend_singles ][ src_id ] + miss_pack_ids ).uniq
          else
            @tun_info[ :resend_singles ][ src_id ] = miss_pack_ids
          end

          add_write( tun )
        when RANGE_MISS then
          return if from_addr != @tun_info[ :tund_addr ]

          src_id, *ranges = data[ 9..-1 ].unpack( 'Q>Q>*' )

          # puts "debug2 got range miss #{ src_id } #{ ranges[ 0, 100 ].inspect }"

          return if ranges.empty? || ranges.size % 2 != 0

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          miss_pack_ids = []
          idx = 0

          while idx < ranges.size do
            miss_pack_ids += src_info[ :wafters ].select{ | pack_id, _ | ( pack_id >= ranges[ idx ] ) && ( pack_id <= ranges[ idx + 1 ] ) }.keys
            idx += 2
          end

          if miss_pack_ids.any? then
            if @tun_info[ :resend_ranges ].include?( src_id ) then
              @tun_info[ :resend_ranges ][ src_id ] = ( @tun_info[ :resend_ranges ][ src_id ] + miss_pack_ids ).uniq
            else
              @tun_info[ :resend_ranges ][ src_id ] = miss_pack_ids
            end

            add_write( tun )
          end
        when CONTINUE then
          src_id, complete_pack_id = data[ 9, 16 ].unpack( 'Q>Q>' )

          # puts "debug2 got continue #{ src_id } #{ complete_pack_id }"

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          src_info[ :wafters ].delete_if{ | pack_id, _ | pack_id <= complete_pack_id }

          if src_info[ :wafters ].any? && !@tun_info[ :resend_newers ].include?( src_id ) then
            @tun_info[ :resend_newers ][ src_id ] = src_info[ :wafters ].keys
            add_write( tun )
          end
        when FIN1 then
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id, fin1_dst_pack_id = data[ 9, 10 ].unpack( 'nQ>' )

          # puts "debug1 got fin1 #{ dst_id } #{ fin1_dst_pack_id }"

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          # 对面可能同时读到和写到reset，导致发出两条fin1
          return if src_info.nil? || src_info[ :fin1_dst_pack_id ]

          src_info[ :fin1_dst_pack_id ] = fin1_dst_pack_id

          # puts "debug1 continue recv #{ src_info[ :continue_recv_pack_id ] } src.wbuff.empty? #{ src_info[ :wbuff ].empty? }"

          if ( src_info[ :continue_recv_pack_id ] == fin1_dst_pack_id ) && src_info[ :wbuff ].empty? then
            src.close_write
            src_info[ :closed_write ] = true
            @writes.delete( src )

            # puts "debug1 add ctlmsg fin2"
            add_ctlmsg_fin2( src_info )

            if src_info[ :dst_fin2 ] then
              # puts "debug1 读tun -> 读到fin1，得到对面dst最终包id -> 已连续写入至dst最终包id？ -> 关src写 -> 发fin2 -> src.dst_fin2？ -> 删src.ext"
              @roles.delete( src )
              del_src_ext( src )
            end
          end
        when FIN2 then
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id = data[ 9, 2 ].unpack( 'n' ).first

          # puts "debug1 got fin2 #{ dst_id }"

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return if src_info.nil? || src_info[ :dst_fin2 ]

          src_info[ :dst_fin2 ] = true

          if src.closed? then
            # puts "debug1 读tun -> 读到fin2，对面已结束写 -> src.dst_fin2置true -> src已双向关？ -> 删src.ext"
            @roles.delete( src )
            del_src_ext( src )
          end
        when TUND_FIN then
          return if from_addr != @tun_info[ :tund_addr ]

          puts "p#{ Process.pid } #{ Time.new } recv tund fin"
          set_tun_is_closing
        when IP_CHANGED then
          return if from_addr != @tun_info[ :tund_addr ]

          puts "p#{ Process.pid } #{ Time.new } recv ip changed"
          set_tun_is_closing
        end

        return
      end

      return if from_addr != @tun_info[ :tund_addr ]

      print "#{ pack_id } "

      dst_id = data[ 8, 2 ].unpack( 'n' ).first

      src_id = @tun_info[ :src_ids ][ dst_id ]
      return unless src_id

      src = @tun_info[ :srcs ][ src_id ]
      return if src.nil? || src.closed?

      src_info = @src_infos[ src ]
      return if ( pack_id <= src_info[ :continue_recv_pack_id ] ) || src_info[ :pieces ].include?( pack_id )

      data = data[ 10..-1 ]

      if pack_id <= CONFUSE_UNTIL then
        data = @custom.decode( data )
        # puts "debug3 decoded pack #{ pack_id } #{ data.bytesize }\n#{ data.inspect }\n\n"
      end

      # 放进src wbuff，跳号放碎片缓存，发确认
      if pack_id - src_info[ :continue_recv_pack_id ] == 1 then
        while src_info[ :pieces ].include?( pack_id + 1 ) do
          data << src_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        src_info[ :continue_recv_pack_id ] = pack_id
        add_src_wbuff( src, data )
      else
        src_info[ :pieces ][ pack_id ] = data
        src_info[ :last_recv_at ] = now
      end
    end

    ##
    # write src
    #
    def write_src( src )
      src_info = @src_infos[ src ]
      return if src_info[ :closed_write ]

      # 处理关闭
      if src_info[ :is_closing ] then
        close_src( src )
        return
      end

      # 处理wbuff
      data = src_info[ :wbuff ]

      unless data.empty? then
        begin
          written = src.write_nonblock( data )
        rescue IO::WaitWritable, Errno::EINTR
          return
        rescue Exception => e
          # puts "debug1 write src #{ e.class }"
          close_src( src )
          return
        end

        # puts "debug3 written src #{ written }"
        data = data[ written..-1 ]
        src_info[ :wbuff ] = data
      end

      unless data.empty? then
        puts "p#{ Process.pid } #{ Time.new } write src cutted? written #{ written } left #{ data.bytesize }"
        return
      end

      dst = src_info[ :dst ]

      if dst then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :closed_read ] then
          src.close_write
          src_info[ :closed_write ] = true

          if src.closed? && src_info[ :rbuff ].empty? then
            # puts "debug1 写src -> 写光src.wbuff -> src.dst？ -> dst已关读？ -> 关src写 -> src已双向关且src.rbuff空？ -> 删src.info"
            @roles.delete( src )
            @src_infos.delete( src )
          end
        end
      elsif src_info[ :dst_id ] then
        if src_info[ :fin1_dst_pack_id ] && ( src_info[ :continue_recv_pack_id ] == src_info[ :fin1_dst_pack_id ] ) then
          src.close_write
          src_info[ :closed_write ] = true

          # puts "debug1 after write src, close src write and add ctlmsg fin2"
          add_ctlmsg_fin2( src_info )

          if src_info[ :dst_fin2 ] then
            # puts "debug1 写src -> 写光src.wbuff -> src.dst_id？ -> 已连续写入至dst最终包id？ -> 关src写 -> 发fin2 -> src.dst_fin2？ -> 删src.ext"
            @roles.delete( src )
            del_src_ext( src )
          end
        end
      end

      @writes.delete( src )
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closed_write ]

      # 处理关闭
      if dst_info[ :is_closing ] then
        close_dst( dst )
        return
      end

      src = dst_info[ :src ]
      src_info = @src_infos[ src ]

      # 中转src的rbuff
      data = src_info[ :rbuff ]

      unless data.empty? then
        begin
          written = dst.write_nonblock( data )
        rescue IO::WaitWritable, Errno::EINTR
          return
        rescue Exception => e
          # puts "debug1 write dst #{ e.class }"
          close_dst( dst )
          return
        end

        data = data[ written..-1 ]
        src_info[ :rbuff ] = data
        # 更新最后中转时间
        src_info[ :last_sent_at ] = Time.new
      end

      unless data.empty? then
        puts "p#{ Process.pid } #{ Time.new } write dst cutted? written #{ written } left #{ data.bytesize }"
        return
      end

      if src_info[ :closed_read ] then
        dst.close_write
        dst_info[ :closed_write ] = true

        if dst.closed? && src_info[ :wbuff ].empty? then
          # puts "debug1 写dst -> 转光dst.src.rbuff -> src已关读？ -> 关dst写 -> dst已双向关且src.wbuff空？ -> 删dst.info"
          @roles.delete( dst )
          @dst_infos.delete( dst )
        end
      end

      @writes.delete( dst )
    end

    ##
    # write tun
    #
    def write_tun( tun )
      # 处理关闭
      if @tun_info[ :is_closing ] then
        close_tun( tun )
        return
      end

      now = Time.new

      # 发ctlmsg
      while @tun_info[ :ctlmsgs ].any? do
        data, to_addr = @tun_info[ :ctlmsgs ].first
        sent = send_data( data, to_addr )

        if sent == :fatal then
          close_tun( tun )
          return
        elsif sent == :wait then
          # puts "debug1 #{ Time.new } wait send ctlmsg left #{ @tun_info[ :ctlmsgs ].size }"
          return
        end

        @tun_info[ :ctlmsgs ].shift
      end

      resend_newers = @tun_info[ :resend_newers ]
      resend_singles = @tun_info[ :resend_singles ]
      resend_ranges = @tun_info[ :resend_ranges ]

      resend_newers.each do | src_id, newer_pack_ids |
        src = @tun_info[ :srcs ][ src_id ]

        if src then
          src_info = @src_infos[ src ]

          while newer_pack_ids.any? do
            pack_id = newer_pack_ids.first
            data = src_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( data )

              if sent == :fatal then
                close_tun( tun )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend newer at #{ pack_id } left #{ newer_pack_ids.size }"
                src_info[ :last_sent_at ] = now
                return
              else
                src_info[ :last_sent_at ] = now
              end
            end

            newer_pack_ids.shift
          end
        end

        resend_newers.delete( src_id )
      end

      resend_singles.each do | src_id, miss_pack_ids |
        src = @tun_info[ :srcs ][ src_id ]

        if src then
          src_info = @src_infos[ src ]

          while miss_pack_ids.any? do
            pack_id = miss_pack_ids.first
            data = src_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( data )

              if sent == :fatal then
                close_tun( tun )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend single at #{ pack_id } left #{ miss_pack_ids.size }"
                src_info[ :last_sent_at ] = now
                return
              else
                src_info[ :last_sent_at ] = now
              end
            end

            miss_pack_ids.shift
          end
        end

        resend_singles.delete( src_id )
      end

      resend_ranges.each do | src_id, miss_pack_ids |
        src = @tun_info[ :srcs ][ src_id ]

        if src then
          src_info = @src_infos[ src ]

          while miss_pack_ids.any? do
            pack_id = miss_pack_ids.first
            data = src_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( data )

              if sent == :fatal then
                close_tun( tun )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend range at #{ pack_id } left #{ miss_pack_ids.size }"
                src_info[ :last_sent_at ] = now
                return
              else
                src_info[ :last_sent_at ] = now
              end
            end

            miss_pack_ids.shift
          end
        end

        resend_ranges.delete( src_id )
      end

      # 处理event srcs
      while @tun_info[ :event_srcs ].any? do
        src = @tun_info[ :event_srcs ].first
        src_info = @src_infos[ src ]
        src_id = src_info[ :id ]
        rbuff = src_info[ :rbuff ]

        unless rbuff.empty? then
          len = rbuff.bytesize
          written = 0
          idx = 0

          while idx < len do
            chunk = rbuff[ idx, PACK_SIZE ]
            chunk_size = chunk.bytesize
            pack_id = src_info[ :biggest_pack_id ] + 1

            if pack_id <= CONFUSE_UNTIL then
              # puts "debug3 encode chunk #{ pack_id } #{ chunk_size }\n#{ chunk.inspect }\n\n"
              chunk = @custom.encode( chunk )
            end

            data = [ [ pack_id, src_id ].pack( 'Q>Q>' ), chunk ].join
            sent = send_data( data )

            if sent == :fatal then
              close_tun( tun )
              return
            elsif sent == :wait then
              # puts "debug1 #{ Time.new } wait relay src.rbuff at #{ pack_id }"
              rbuff = rbuff[ written..-1 ]
              src_info[ :rbuff ] = rbuff
              src_info[ :last_sent_at ] = now
              return
            end

            src_info[ :wafters ][ pack_id ] = data
            src_info[ :biggest_pack_id ] = pack_id
            written += chunk_size
            idx += PACK_SIZE
          end

          if written != len then
            puts "p#{ Process.pid } #{ Time.new } relay src.rbuff cutted? #{ written }/#{ len }"
            return
          end

          src_info[ :rbuff ].clear
          src_info[ :last_sent_at ] = now

          # 写后超过上限，暂停读src
          if src_info[ :wafters ].size >= WAFTERS_LIMIT then
            puts "p#{ Process.pid } #{ Time.new } pause src #{ src_id } #{ src_info[ :destination_domain ] } #{ src_info[ :biggest_pack_id ] }"
            @reads.delete( src )
            src_info[ :paused ] = true
          end
        end

        if src_info[ :closed_read ] then
          # puts "debug1 写tun -> 转光src.rbuff -> src已关读？ -> 发fin1"
          add_ctlmsg_fin1( src_info )
        end

        @tun_info[ :event_srcs ].shift
      end

      @tun_info[ :last_sent_at ] = now

      if @tun_info[ :ctlmsgs ].empty? && @tun_info[ :event_srcs ].empty? then
        @writes.delete( tun )
      end
    end

  end
end
