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
      @pause_srcs = []
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
          # 先写，再读
          ws.each do | sock |
            case @roles[ sock ]
            when :src
              write_src( sock )
            when :dst
              write_dst( sock )
            when :tun
              write_tun( sock )
            end
          end

          rs.each do | sock |
            case @roles[ sock ]
            when :dotr
              read_dotr( sock )
            when :proxy
              read_proxy( sock )
            when :src
              read_src( sock )
            when :dst
              read_dst( sock )
            when :tun
              read_tun( sock )
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
      if @tun && !@tun.closed? && @tun_info[ :tund_addr ]
        # puts "debug1 send tun fin"
        data = [ 0, TUN_FIN ].pack( 'Q>C' )
        @tun.sendmsg( data, 0, @tun_info[ :tund_addr ] )
      end

      # puts "debug1 exit"
      exit
    end

    private

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

            if @tun && !@tun.closed?
              is_expired = @tun_info[ :last_recv_at ] ? ( now - @tun_info[ :last_recv_at ] > EXPIRE_AFTER ) : ( now - @tun_info[ :created_at ] > EXPIRE_NEW )

              if is_expired
                puts "p#{ Process.pid } #{ Time.new } expire tun"
                set_is_closing( @tun )
                trigger = true
              else
                data = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'Q>CC' )
                # puts "debug1 #{ Time.new } heartbeat"
                send_data( @tun, data, @tun_info[ :tund_addr ] )
                del_src_ids = []

                @tun_info[ :srcs ].each do | src_id, src |
                  if src.closed?
                    src_info = @src_infos[ src ]

                    if src_info && ( now - src_info[ :last_continue_at ] > EXPIRE_AFTER )
                      puts "p#{ Process.pid } #{ Time.new } expire src ext #{ src_info[ :destination_domain ] }"
                      @tun_info[ :wmems ].delete_if { | src_id_pack_id, _ | src_id_pack_id.first == src_id }
                      @tun_info[ :src_ids ].delete( src_info[ :dst_id ] )
                      @src_infos.delete( src )
                      del_src_ids << src_id
                    end
                  end
                end

                if del_src_ids.any?
                  @tun_info[ :srcs ].delete_if { | src_id, _ | del_src_ids.include?( src_id ) }
                end
              end
            end

            @src_infos.each do | src, src_info |
              if now - src_info[ :last_continue_at ] > EXPIRE_AFTER
                puts "p#{ Process.pid } #{ Time.new } expire src #{ src_info[ :destination_domain ] }"
                set_is_closing( src )
                trigger = true
              end
            end

            @dst_infos.each do | dst, dst_info |
              if now - dst_info[ :last_continue_at ] > EXPIRE_AFTER
                puts "p#{ Process.pid } #{ Time.new } expire dst #{ dst_info[ :domain ] }"
                set_is_closing( dst )
                trigger = true
              end
            end

            if trigger
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
            if @tun && !@tun.closed? && @tun_info[ :tund_addr ]
              if @tun_info[ :srcs ].any?
                now = Time.new

                @tun_info[ :srcs ].each do | src_id, src |
                  src_info = @src_infos[ src ]

                  if src_info && src_info[ :dst_id ] && ( now - src_info[ :last_continue_at ] < SEND_STATUS_UNTIL )
                    data = [ 0, SOURCE_STATUS, src_id, src_info[ :biggest_pack_id ], src_info[ :continue_dst_pack_id ] ].pack( 'Q>CQ>Q>Q>' )
                    send_data( @tun, data, @tun_info[ :tund_addr ] )
                  end
                end
              end

              if @pause_srcs.any? && ( @tun_info[ :wmems ].size < RESUME_BELOW )
                trigger = false

                @pause_srcs.each do | src |
                  src_info = @src_infos[ src ]

                  if src_info
                    puts "p#{ Process.pid } #{ Time.new } resume src #{ src_info[ :destination_domain ] }"
                    add_read( src )
                    trigger = true
                  end
                end

                @pause_srcs.clear

                if trigger
                  next_tick
                end
              end
            end
          end
        end
      end
    end

    ##
    # loop send hello
    #
    def loop_send_hello
      data = @custom.hello

      Thread.new do
        EXPIRE_NEW.times do | i |
          if @tun.closed? || @tun_info[ :tund_addr ]
            # puts "debug1 break loop send hello"
            break
          end

          @mutex.synchronize do
            msg = i >= 1 ? "resend hello #{ i }" : "hello i'm tun"
            puts "p#{ Process.pid } #{ Time.new } #{ msg }"
            # puts "debug1 #{ data.inspect }"

            send_data( @tun, data, @proxyd_addr )
          end

          sleep CHECK_STATUS_INTERVAL
        end
      end
    end

    ##
    # loop send a new source
    #
    def loop_send_a_new_source( src )
      src_info = @src_infos[ src ]

      if src_info
        destination_domain = src_info[ :destination_domain ]
        destination_port = src_info[ :destination_port ]
        domain_port = [ destination_domain, destination_port ].join( ':' )
        data = [ [ 0, A_NEW_SOURCE, src_info[ :id ] ].pack( 'Q>CQ>' ), @custom.encode( domain_port ) ].join

        Thread.new do
          EXPIRE_NEW.times do | i |
            if @tun.nil? || @tun.closed? || src.closed? || src_info[ :dst_id ]
              # puts "debug1 break loop send a new source #{ src_info[ :dst_port ] }"
              break
            end

            @mutex.synchronize do
              if i >= 1
                puts "p#{ Process.pid } #{ Time.new } resend a new source #{ domain_port } #{ i }"
              end

              send_data( @tun, data, @tun_info[ :tund_addr ] )
            end

            sleep CHECK_STATUS_INTERVAL
          end
        end
      end
    end

    ##
    # resolve domain
    #
    def resolve_domain( src, domain )
      if @remotes.any? { | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) }
        # puts "debug1 #{ domain } hit remotes"
        new_a_src_ext( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache
        ip_info, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE
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
          if ip_info
            @resolv_caches[ domain ] = [ ip_info, Time.new ]

            unless src.closed?
              puts "p#{ Process.pid } #{ Time.new } resolved #{ domain } #{ ip_info.ip_address }"
              deal_with_destination_ip( src, ip_info )
            end
          else
            set_is_closing( src )
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

      if ( @directs.any? { | direct | direct.include?( ip_info.ip_address ) } ) || ( ( src_info[ :destination_domain ] == @proxyd_host ) && ![ 80, 443 ].include?( src_info[ :destination_port ] ) )
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

      if RUBY_PLATFORM.include?( 'linux' )
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
        port: port,           # 端口
        pending_sources: [],  # 还没配上tund，暂存的src
        wbuffs: [],           # 写前 [ src_id, pack_id, data ]
        wmems: {},            # 写后 [ src_id, pack_id ] => data
        tund_addr: nil,       # tund地址
        srcs: {},             # src_id => src
        src_ids: {},          # dst_id => src_id
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间，过期关闭
        is_closing: false     # 是否准备关闭
      }

      @tun = tun
      @tun_info = tun_info

      add_read( tun, :tun )
      loop_send_hello
    end

    ##
    # new a dst
    #
    def new_a_dst( src, ip_info )
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      destination_addr = Socket.sockaddr_in( src_info[ :destination_port ], ip_info.ip_address )
      dst = Socket.new( ip_info.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )

      if RUBY_PLATFORM.include?( 'linux' )
        dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable，这里仅仅接一下，逻辑写外面，整齐
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ e.class }, close src"
        set_is_closing( src )
        return
      end

      # puts "debug1 a new dst #{ dst.local_address.inspect }"
      local_port = dst.local_address.ip_port
      @dst_infos[ dst ] = {
        local_port: local_port,     # 本地端口
        src: src,                   # 对应src
        domain: domain,             # 域名
        wbuff: '',                  # 写前
        last_continue_at: Time.new, # 上一次发生流量的时间
        is_closing: false           # 是否准备关闭
      }

      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http
        if src_info[ :is_connect ]
          # puts "debug1 add src wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        else
          # puts "debug1 add src rbuff to dst wbuff"
          add_dst_wbuff( dst, src_info[ :rbuff ] )
        end
      elsif src_info[ :proxy_proto ] == :socks5
        add_src_wbuff_socks5_conn_reply( src )
      end
    end

    ##
    # new a src ext
    #
    def new_a_src_ext( src )
      if @tun.nil? || @tun.closed?
        new_a_tun
      end

      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :tunnel
      src_id = src_info[ :id ]
      @tun_info[ :srcs ][ src_id ] = src

      if @tun_info[ :tund_addr ]
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

      if lines.empty?
        return [ data, nil ]
      end

      method, url, proto = lines.first.split( ' ' )

      if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://'
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
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      if sock && !sock.closed? && !@reads.include?( sock )
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
      if sock && !sock.closed? && !@writes.include?( sock )
        @writes << sock
      end
    end

    ##
    # add pause src
    #
    def add_pause_src( src )
      @reads.delete( src )

      unless @pause_srcs.include?( src )
        @pause_srcs << src
      end
    end

    ##
    # set is closing
    #
    def set_is_closing( sock )
      if sock && !sock.closed?
        role = @roles[ sock ]
        # puts "debug1 set #{ role.to_s } is closing"

        case role
        when :src
          src_info = @src_infos[ sock ]
          src_info[ :is_closing ] = true
        when :dst
          dst_info = @dst_infos[ sock ]
          dst_info[ :is_closing ] = true
        when :tun
          @tun_info[ :is_closing ] = true
        end

        @reads.delete( sock )
        add_write( sock )
      end
    end

    ##
    # tunnel data
    #
    def tunnel_data( src, data )
      now = Time.new
      src_info = @src_infos[ src ]
      src_id = src_info[ :id ]
      pack_id = src_info[ :biggest_pack_id ]
      idx = 0
      len = data.bytesize

      while idx < len
        chunk = data[ idx, PACK_SIZE ]
        pack_id += 1

        if pack_id <= CONFUSE_UNTIL
          chunk = @custom.encode( chunk )
          # puts "debug1 encoded chunk #{ pack_id }"
        end

        data2 = [ [ pack_id, src_id ].pack( 'Q>Q>' ), chunk ].join
        sent = send_data( @tun, data2, @tun_info[ :tund_addr ] )
        # puts "debug2 written pack #{ pack_id } #{ sent }"
        @tun_info[ :wmems ][ [ src_id, pack_id ] ] = data2
        src_info[ :send_ats ][ pack_id ] = now
        idx += PACK_SIZE
      end

      src_info[ :biggest_pack_id ] = pack_id
      src_info[ :last_continue_at ] = now

      # 写后超过上限，暂停读src
      if @tun_info[ :wmems ].size >= WMEMS_LIMIT
        puts "p#{ Process.pid } #{ Time.new } pause src #{ src_id } #{ src_info[ :destination_domain ] } #{ src_info[ :biggest_pack_id ] }"
        add_pause_src( src )
      end
    end

    ##
    # send data
    #
    def send_data( tun, data, to_addr )
      unless to_addr
        return false
      end

      begin
        tun.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        puts "#{ Time.new } #{ e.class }, close tun"
        close_tun( tun )
        return false
      end

      true
    end

    ##
    # close src
    #
    def close_src( src )
      # puts "debug1 close src"
      close_sock( src )
      @pause_srcs.delete( src )
      src_info = @src_infos[ src ]

      if src_info[ :proxy_type ] == :direct
        @src_infos.delete( src )

        if src_info[ :dst ]
          set_is_closing( src_info[ :dst ] )
        end

        return
      end

      if @tun.closed? || src_info[ :dst_id ].nil?
        @src_infos.delete( src )
        return
      end

      src_id = src_info[ :id ]

      if src_info[ :is_dst_closed ]
        # puts "debug1 2-3. after close src -> dst closed ? yes -> del src ext -> send fin2"
        del_src_ext( src_id )
        data = [ 0, FIN2, src_id ].pack( 'Q>CQ>' )
      else
        # puts "debug1 1-1. after close src -> dst closed ? no -> send fin1"
        data = [ 0, FIN1, src_id, src_info[ :biggest_pack_id ], src_info[ :continue_dst_pack_id ] ].pack( 'Q>CQ>Q>Q>' )
      end

      send_data( @tun, data, @tun_info[ :tund_addr ] )
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      set_is_closing( dst_info[ :src ] )
    end

    ##
    # close tun
    #
    def close_tun( tun )
      # puts "debug1 close tun"
      close_sock( tun )
      @tun_info[ :srcs ].each{ | _, src | set_is_closing( src ) }
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
    # del src ext
    #
    def del_src_ext( src_id )
      src = @tun_info[ :srcs ][ src_id ]

      if src && src.closed?
        @tun_info[ :wmems ].delete_if { | src_id_pack_id, _ | src_id_pack_id.first == src_id }
        @tun_info[ :srcs ].delete( src_id )
        src_info = @src_infos.delete( src )

        if src_info
          @tun_info[ :src_ids ].delete( src_info[ :dst_id ] )
        end
      end
    end

    ##
    # release wmems
    #
    def release_wmems( src_info, completed_pack_id )
      if completed_pack_id > src_info[ :completed_pack_id ]
        # puts "debug2 update completed pack #{ completed_pack_id }"
        pack_ids = src_info[ :send_ats ].keys.select { | pack_id | pack_id <= completed_pack_id }

        pack_ids.each do | pack_id |
          @tun_info[ :wmems ].delete( [ src_info[ :id ], pack_id ] )
          src_info[ :send_ats ].delete( pack_id )
        end

        src_info[ :completed_pack_id ] = completed_pack_id
      end
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # write src
    #
    def write_src( src )
      src_info = @src_infos[ src ]

      if src_info[ :is_closing ]
        close_src( src )
        return
      end

      data = src_info[ :wbuff ]

      if data.empty?
        @writes.delete( src )
        return
      end

      begin
        written = src.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        return
      rescue Exception => e
        close_src( src )
        return
      end

      # puts "debug2 write src #{ written }"
      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
      src_info[ :last_continue_at ] = Time.new
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]

      if dst_info[ :is_closing ]
        close_dst( dst )
        return
      end

      data = dst_info[ :wbuff ]

      if data.empty?
        @writes.delete( dst )
        return
      end

      begin
        written = dst.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 write dst #{ e.class }"
        close_dst( dst )
        return
      end

      # puts "debug2 write dst #{ written }"
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      dst_info[ :last_continue_at ] = Time.new
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if @tun_info[ :is_closing ]
        close_tun( tun )
        return
      end

      @writes.delete( tun )
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
        id: src_id,                 # id
        proxy_proto: :uncheck,      # :uncheck / :http / :socks5
        proxy_type: :uncheck,       # :uncheck / :checking / :direct / :tunnel / :negotiation
        dst: nil,                   # :direct的场合，对应的dst
        destination_domain: nil,    # 目的地域名
        destination_port: nil,      # 目的地端口
        biggest_pack_id: 0,         # 最大包号码
        is_connect: true,           # 代理协议是http的场合，是否是CONNECT
        rbuff: '',                  # 非CONNECT，dst或者远端dst未准备好，暂存流量
        wbuff: '',                  # 写前
        dst_id: nil,                # 远端dst id
        send_ats: {},               # 上一次发出时间 pack_id => send_at
        continue_dst_pack_id: 0,    # 收到几
        pieces: {},                 # 跳号包 dst_pack_id => data
        is_dst_closed: false,       # dst是否已关闭
        biggest_dst_pack_id: 0,     # dst最大包号码
        completed_pack_id: 0,       # 完成到几（对面收到几）
        last_continue_at: Time.new, # 上一次发生流量的时间
        is_closing: false           # 是否准备关闭
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
        set_is_closing( src )
        return
      end

      # puts "debug2 read src #{ data.inspect }"
      src_info = @src_infos[ src ]
      src_info[ :last_continue_at ] = Time.new
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck
        if data[ 0, 7 ] == 'CONNECT'
          # puts "debug1 CONNECT"
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port
            puts "p#{ Process.pid } #{ Time.new } CONNECT miss domain"
            set_is_closing( src )
            return
          end
        elsif data[ 0 ].unpack( 'C' ).first == 5
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

          unless methods.include?( 0 )
            puts "p#{ Process.pid } #{ Time.new } miss method 00"
            set_is_closing( src )
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

          unless host_line
            # puts "debug1 not found host line"
            set_is_closing( src )
            return
          end

          data, domain_port = sub_http_request( data )

          unless domain_port
            # puts "debug1 not HTTP"
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port
              puts "p#{ Process.pid } #{ Time.new } Host line miss domain"
              set_is_closing( src )
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
      when :checking
        # puts "debug1 add src rbuff while checking #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :negotiation
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        # puts "debug1 negotiation #{ data.inspect }"
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1
          # puts "debug1 socks5 CONNECT"

          if atyp == 1
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )
            destination_addr = Socket.sockaddr_in( destination_port, destination_host )
            destination_addrinfo = Addrinfo.new( destination_addr )
            destination_ip = destination_addrinfo.ip_address
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            # puts "debug1 IP V4 address #{ destination_addrinfo.inspect }"
            deal_with_destination_ip( src, destination_addrinfo )
          elsif atyp == 3
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize
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
      when :tunnel
        if src_info[ :dst_id ]
          if @tun.closed?
            # puts "debug1 tun closed, close src"
            set_is_closing( src )
            return
          end

          unless src_info[ :is_connect ]
            data, _ = sub_http_request( data )
          end

          tunnel_data( src, data )
        else
          # puts "debug1 remote dst not ready, save data to src rbuff"
          src_info[ :rbuff ] << data
        end
      when :direct
        dst = src_info[ :dst ]

        if dst
          if dst.closed?
            # puts "debug1 dst closed, close src"
            set_is_closing( src )
            return
          end

          unless src_info[ :is_connect ]
            data, _ = sub_http_request( data )
          end

          add_dst_wbuff( dst, data )
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
        set_is_closing( dst )
        return
      end

      # puts "debug2 read dst #{ data.inspect }"
      dst_info = @dst_infos[ dst ]
      dst_info[ :last_continue_at ] = Time.new
      src = dst_info[ :src ]

      if src.closed?
        puts "p#{ Process.pid } #{ Time.new } src closed, close dst #{ dst_info[ :domain ] }"
        set_is_closing( dst )
        return
      end

      add_src_wbuff( src, data )
    end

    ##
    # read tun
    #
    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      from_addr = addrinfo.to_sockaddr
      now = Time.new
      @tun_info[ :last_recv_at ] = now
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if pack_id == 0
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when TUND_PORT
          return if ( from_addr != @proxyd_addr ) || @tun_info[ :tund_addr ]

          tund_port = data[ 9, 2 ].unpack( 'n' ).first

          puts "p#{ Process.pid } #{ Time.new } got tund port #{ tund_port }"
          tund_addr = Socket.sockaddr_in( tund_port, @proxyd_host )
          @tun_info[ :tund_addr ] = tund_addr

          if @tun_info[ :pending_sources ].any?
            puts "p#{ Process.pid } #{ Time.new } send pending sources"

            @tun_info[ :pending_sources ].each do | src |
              loop_send_a_new_source( src )
            end

            @tun_info[ :pending_sources ].clear
          end
        when PAIRED
          return if from_addr != @tun_info[ :tund_addr ]

          src_id, dst_id = data[ 9, 10 ].unpack( 'Q>n' )

          src = @tun_info[ :srcs ][ src_id ]
          return if src.nil? || src.closed?

          src_info = @src_infos[ src ]
          return if src_info.nil? || src_info[ :dst_id ]

          # puts "debug1 got paired #{ src_id } #{ dst_id }"

          if dst_id == 0
            set_is_closing( src )
            return
          end

          src_info[ :dst_id ] = dst_id
          @tun_info[ :src_ids ][ dst_id ] = src_id

          if src_info[ :proxy_proto ] == :http
            if src_info[ :is_connect ]
              # puts "debug1 add src wbuff http ok"
              add_src_wbuff( src, HTTP_OK )
            else
              # puts "debug1 send src rbuff to tund"
              tunnel_data( src, src_info[ :rbuff ] )
            end
          elsif src_info[ :proxy_proto ] == :socks5
            add_src_wbuff_socks5_conn_reply( src )
          end
        when DEST_STATUS
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id, relay_dst_pack_id, continue_src_pack_id = data[ 9, 18 ].unpack( 'nQ>Q>' )

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          # puts "debug2 got dest status #{ Time.new }"

          # 消写后
          release_wmems( src_info, continue_src_pack_id )

          # 发miss
          if !src.closed? && ( src_info[ :continue_dst_pack_id ] < relay_dst_pack_id )
            ranges = []
            ignored = false
            curr_pack_id = src_info[ :continue_dst_pack_id ] + 1

            src_info[ :pieces ].keys.sort.each do | pack_id |
              if pack_id > curr_pack_id
                ranges << [ curr_pack_id, pack_id - 1 ]

                if ranges.size >= MISS_RANGE_LIMIT
                  puts "p#{ Process.pid } #{ Time.new } break add miss range at #{ pack_id }"
                  ignored = true
                  break
                end
              end

              curr_pack_id = pack_id + 1
            end

            if !ignored && ( curr_pack_id <= relay_dst_pack_id )
              ranges << [ curr_pack_id, relay_dst_pack_id ]
            end

            # puts "debug1 continue/relay #{ src_info[ :continue_dst_pack_id ] }/#{ relay_dst_pack_id } send MISS #{ ranges.size }"
            idx = 0
            ranges = ranges.map{ | pack_id_begin, pack_id_end | [ pack_id_begin, pack_id_end ].pack( 'Q>Q>' ) }

            while idx < ranges.size
              chunk = ranges[ idx, MULTI_MISS_SIZE ].join
              data2 = [ [ 0, MULTI_MISS, dst_id ].pack( 'Q>Cn' ), chunk ].join
              send_data( tun, data2, @tun_info[ :tund_addr ] )
              idx += MULTI_MISS_SIZE
            end
          end
        when MULTI_MISS
          src_id, *ranges = data[ 9..-1 ].unpack( 'Q>Q>*' )

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          return if ranges.empty? || ( ranges.size % 2 != 0 )

          # puts "debug1 got multi miss #{ src_id } #{ ranges.size }"

          idx = 0

          while idx < ranges.size
            pack_id_begin, pack_id_end = ranges[ idx ], ranges[ idx + 1 ]

            ( pack_id_begin..pack_id_end ).each do | pack_id |
              send_at = src_info[ :send_ats ][ pack_id ]

              if send_at
                break if now - send_at < CHECK_STATUS_INTERVAL
                data2 = @tun_info[ :wmems ][ [ src_id, pack_id ] ]

                if data2
                  if send_data( tun, data2, @tun_info[ :tund_addr ] )
                    src_info[ :last_continue_at ] = now
                  end
                end
              end
            end

            idx += 2
          end
        when MISS
          return if from_addr != @tun_info[ :tund_addr ]

          src_id, pack_id_begin, pack_id_end = data[ 9, 24 ].unpack( 'Q>Q>Q>' )

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            send_at = src_info[ :send_ats ][ pack_id ]

            if send_at
              break if now - send_at < CHECK_STATUS_INTERVAL
              data2 = @tun_info[ :wmems ][ [ src_id, pack_id ] ]

              if data2
                if send_data( tun, data2, @tun_info[ :tund_addr ] )
                  src_info[ :last_continue_at ] = now
                end
              end
            end
          end
        when FIN1
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id, biggest_dst_pack_id, continue_src_pack_id = data[ 9, 18 ].unpack( 'nQ>Q>' )

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          # puts "debug1 got fin1 #{ dst_id } biggest dst pack #{ biggest_dst_pack_id } completed src pack #{ continue_src_pack_id }"
          src_info[ :is_dst_closed ] = true
          src_info[ :biggest_dst_pack_id ] = biggest_dst_pack_id
          release_wmems( src_info, continue_src_pack_id )

          if ( biggest_dst_pack_id == src_info[ :continue_dst_pack_id ] )
            # puts "debug1 2-1. tun recv fin1 -> all traffic received ? -> close src after write"
            set_is_closing( src )
          end
        when FIN2
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id = data[ 9, 2 ].unpack( 'n' ).first

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          # puts "debug1 1-2. tun recv fin2 -> del src ext"
          del_src_ext( src_id )
        when TUND_FIN
          return if from_addr != @tun_info[ :tund_addr ]

          puts "p#{ Process.pid } #{ Time.new } recv tund fin"
          set_is_closing( tun )
        when IP_CHANGED
          return if from_addr != @tun_info[ :tund_addr ]

          puts "p#{ Process.pid } #{ Time.new } recv ip changed"
          set_is_closing( tun )
        end

        return
      end

      return if from_addr != @tun_info[ :tund_addr ]

      dst_id = data[ 8, 2 ].unpack( 'n' ).first

      src_id = @tun_info[ :src_ids ][ dst_id ]
      return unless src_id

      src = @tun_info[ :srcs ][ src_id ]
      return if src.nil? || src.closed?

      src_info = @src_infos[ src ]
      return unless src_info

      return if ( pack_id <= src_info[ :continue_dst_pack_id ] ) || src_info[ :pieces ].include?( pack_id )

      data = data[ 10..-1 ]
      # puts "debug2 got pack #{ pack_id }"

      if pack_id <= CONFUSE_UNTIL
        # puts "debug2 #{ data.inspect }"
        data = @custom.decode( data )
        # puts "debug1 decoded pack #{ pack_id }"
      end

      # 放进写前，跳号放碎片缓存
      if pack_id - src_info[ :continue_dst_pack_id ] == 1
        while src_info[ :pieces ].include?( pack_id + 1 )
          data << src_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        src_info[ :continue_dst_pack_id ] = pack_id
        src_info[ :last_continue_at ] = now
        add_src_wbuff( src, data )
        # puts "debug2 update continue dst pack #{ pack_id }"

        # 若对面已关闭，且流量正好收全，关闭src
        if src_info[ :is_dst_closed ] && ( pack_id == src_info[ :biggest_dst_pack_id ] )
          # puts "debug1 2-2. tun recv traffic -> dst closed and all traffic received ? -> close src after write"
          set_is_closing( src )
        end
      else
        src_info[ :pieces ][ pack_id ] = data
        src_info[ :last_continue_at ] = now
      end
    end

  end
end
