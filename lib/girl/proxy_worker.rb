module Girl
  class ProxyWorker

    ##
    # initialize
    #
    def initialize( proxy_port, proxyd_host, proxyd_port, directs, remotes, src_chunk_dir, dst_chunk_dir, tun_chunk_dir, im )
      @proxyd_host = proxyd_host
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @directs = directs
      @remotes = remotes
      @src_chunk_dir = src_chunk_dir
      @dst_chunk_dir = dst_chunk_dir
      @tun_chunk_dir = tun_chunk_dir
      @custom = Girl::ProxyCustom.new( im )
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}         # sock => :dotr / :proxy / :src / :dst / :tun
      @src_infos = {}     # src => {}
      @dsts = {}          # local_port => dst
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
            need_trigger = false
            now = Time.new

            if @tun && !@tun.closed?
              is_expired = @tun_info[ :last_recv_at ] ? ( now - @tun_info[ :last_recv_at ] > EXPIRE_AFTER ) : ( now - @tun_info[ :created_at ] > EXPIRE_NEW )

              if is_expired
                puts "p#{ Process.pid } #{ Time.new } expire tun"
                set_is_closing( @tun )
              else
                data = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'Q>CC' )
                add_tun_ctlmsg( data )

                @tun_info[ :src_exts ].each do | src_addr, src_ext |
                  if src_ext[ :src ].closed? && ( now - src_ext[ :last_continue_at ] > EXPIRE_AFTER )
                    puts "p#{ Process.pid } #{ Time.new } expire src_ext"
                    del_src_ext( src_addr )
                  end
                end
              end

              need_trigger = true
            end

            @src_infos.each do | src, src_info |
              is_expired = src_info[ :last_recv_at ].nil? && ( now - src_info[ :created_at ] > EXPIRE_NEW )

              if is_expired
                puts "p#{ Process.pid } #{ Time.new } expire src"
                set_is_closing( src )
                need_trigger = true
              end
            end

            @dst_infos.each do | dst, dst_info |
              is_expired = dst_info[ :last_recv_at ].nil?  && ( now - dst_info[ :created_at ] > EXPIRE_NEW )

              if is_expired
                puts "p#{ Process.pid } #{ Time.new } expire dst"
                set_is_closing( dst )
                need_trigger = true
              end
            end

            if need_trigger
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
          sleep STATUS_INTERVAL

          @mutex.synchronize do
            if @tun && !@tun.closed? && @tun_info[ :tund_addr ]
              need_trigger = false

              if @tun_info[ :src_exts ].any?
                now = Time.new

                @tun_info[ :src_exts ].each do | src_addr, src_ext |
                  if src_ext[ :dst_port ] && ( now - src_ext[ :last_continue_at ] < SEND_STATUS_UNTIL )
                    # puts "debug2 ctl send status biggest #{ src_ext[ :biggest_pack_id ] } continue dst #{ src_ext[ :continue_dst_pack_id ] }"
                    data = [ [ 0, SOURCE_STATUS ].pack( 'Q>C' ), src_addr, [ src_ext[ :biggest_pack_id ], src_ext[ :continue_dst_pack_id ] ].pack( 'Q>Q>' ) ].join
                    add_tun_ctlmsg( data )
                    need_trigger = true
                  end
                end
              end

              if @tun_info[ :paused ] && ( @tun_info[ :src_exts ].map{ | _, src_ext | src_ext[ :wmems ].size }.sum < RESUME_BELOW )
                puts "p#{ Process.pid } #{ Time.new } resume tun"
                @tun_info[ :paused ] = false
                add_write( @tun )
                need_trigger = true
              end

              if need_trigger
                next_tick
              end
            end
          end
        end
      end
    end

    ##
    # loop send a new source
    #
    def loop_send_a_new_source( src_ext, data )
      Thread.new do
        EXPIRE_NEW.times do
          if src_ext[ :src ].closed? || src_ext[ :dst_port ]
            # puts "debug1 break loop send a new source #{ src_ext[ :dst_port ] }"
            break
          end

          @mutex.synchronize do
            # puts "debug1 send a new source #{ data.inspect }"
            add_tun_ctlmsg( data )
            next_tick
          end

          sleep 1
        end
      end
    end

    ##
    # resolve domain
    #
    def resolve_domain( src, domain )
      if ( /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z/ =~ domain ) && domain.split( '.' ).all? { | part | part.to_i < 256 }
        # puts "debug1 #{ domain } is a ip"
        deal_with_destination_ip( src, domain )
        return
      end

      if @remotes.any? { | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) }
        # puts "debug1 #{ domain } hit remotes"
        new_a_src_ext( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache
        destination_ip, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE
          # puts "debug1 #{ domain } hit resolv cache #{ destination_ip }"
          deal_with_destination_ip( src, destination_ip )
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
            destination_ip = ip_info.ip_address
            # puts "debug1 resolved #{ domain } #{ destination_ip }"
            @resolv_caches[ domain ] = [ destination_ip, Time.new ]

            unless src.closed?
              deal_with_destination_ip( src, destination_ip )
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
    def deal_with_destination_ip( src, destination_ip )
      if @directs.any? { | direct | direct.include?( destination_ip ) }
        # ip命中直连列表，直连
        # puts "debug1 #{ destination_ip } hit directs"
        new_a_dst( src, destination_ip )
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
      port = tun.local_address.ip_unpack.last
      tun_info = {
        port: port,           # 端口
        ctlmsg_rbuffs: [],    # 还没配上tund，暂存的ctlmsg
        ctlmsgs: [],          # [ to_addr, data ]
        wbuffs: [],           # 写前缓存 [ src_addr, data ]
        caches: [],           # 块读出缓存 [ src_addr, data ]
        chunks: [],           # 块队列 filename
        spring: 0,            # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        tund_addr: nil,       # tund地址
        src_exts: {},         # src额外信息 src_addr => {}
        src_addrs: {},        # dst_port => src_addr
        paused: false,        # 是否暂停写
        resendings: [],       # 重传队列 [ src_addr, pack_id ]
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间，过期关闭
        is_closing: false     # 是否准备关闭
      }

      @tun = tun
      @tun_info = tun_info

      add_read( tun, :tun )
      data = @custom.hello
      puts "p#{ Process.pid } #{ Time.new } hello i'm tun"
      # puts "debug1 #{ data.inspect }"
      add_tun_ctlmsg( data, @proxyd_addr )
    end

    ##
    # new a dst
    #
    def new_a_dst( src, destination_ip )
      src_info = @src_infos[ src ]
      destination_addr = Socket.sockaddr_in( src_info[ :destination_port ], destination_ip )
      dst = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )

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
      local_port = dst.local_address.ip_unpack
      @dsts[ local_port ] = dst
      @dst_infos[ dst ] = {
        local_port: local_port, # 本地端口
        src: src,               # 对应src
        wbuff: '',              # 写前
        cache: '',              # 块读出缓存
        chunks: [],             # 块队列，写前达到块大小时结一个块 filename
        spring: 0,              # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        created_at: Time.new,   # 创建时间
        last_recv_at: nil,      # 上一次收到流量的时间，过期关闭
        is_closing: false       # 是否准备关闭
      }

      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http
        datas = src_info[ :rbuffs ]

        if datas.empty?
          # CONNECT
          # puts "debug1 add src wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        else
          # not CONNECT
          # puts "debug1 add src rbuffs to dst wbuff"

          datas.each do | data |
            add_dst_wbuff( dst, data )
          end
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

      src_ext = {
        src: src,                  # src
        dst_port: nil,             # 远端dst端口
        wmems: {},                 # 写后 pack_id => data
        send_ats: {},              # 上一次发出时间 pack_id => send_at
        biggest_pack_id: 0,        # 发到几
        continue_dst_pack_id: 0,   # 收到几
        pieces: {},                # 跳号包 dst_pack_id => data
        is_dst_closed: false,      # 对面是否已关闭
        biggest_dst_pack_id: 0,    # 对面发到几
        completed_pack_id: 0,      # 完成到几（对面收到几）
        last_continue_at: Time.new # 创建，或者上一次收到连续流量，或者发出新包的时间
      }

      src_info = @src_infos[ src ]
      src_addr = src_info[ :src_addr ]
      @tun_info[ :src_exts ][ src_addr ] = src_ext
      src_info[ :proxy_type ] = :tunnel

      destination_port = src_info[ :destination_port ]
      destination_domain = src_info[ :destination_domain ]
      destination_domain_port = [ destination_domain, destination_port ].join( ':' )
      data = [ [ 0, A_NEW_SOURCE ].pack( 'Q>C' ), src_addr, @custom.encode( destination_domain_port ) ].join
      loop_send_a_new_source( src_ext, data )
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
      method, url, proto = data.split( "\r\n" ).first.split( ' ' )

      if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://'
        domain_and_port = url.split( '/' )[ 2 ]
        data = data.sub( "http://#{ domain_and_port }", '' )
        # puts "debug1 subed #{ data.inspect } #{ domain_and_port }"
      end

      [ data, domain_and_port ]
    end

    ##
    # add tun ctlmsg
    #
    def add_tun_ctlmsg( data, to_addr = nil )
      unless to_addr
        to_addr = @tun_info[ :tund_addr ]
      end

      if to_addr
        @tun_info[ :ctlmsgs ] << [ to_addr, data ]
        add_write( @tun )
      else
        @tun_info[ :ctlmsg_rbuffs ] << data
      end
    end

    ##
    # add tun wbuff
    #
    def add_tun_wbuff( src_addr, data )
      @tun_info[ :wbuffs ] << [ src_addr, data ]

      if @tun_info[ :wbuffs ].size >= WBUFFS_LIMIT
        spring = @tun_info[ :chunks ].size > 0 ? ( @tun_info[ :spring ] + 1 ) : 0
        filename = "#{ Process.pid }-#{ @tun_info[ :port ] }.#{ spring }"
        chunk_path = File.join( @tun_chunk_dir, filename )
        wbuffs = @tun_info[ :wbuffs ].map{ | _src_addr, _data | [ _src_addr, _data.bytesize.pack( 'n' ), _data ].join }

        begin
          IO.binwrite( chunk_path, wbuffs.join )
        rescue Errno::ENOSPC => e
          puts "p#{ Process.pid } #{ Time.new } #{ e.class }, close tun"
          set_is_closing( @tun )
          return
        end

        @tun_info[ :chunks ] << filename
        @tun_info[ :spring ] = spring
        @tun_info[ :wbuffs ].clear
      end

      add_write( @tun )
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data

      if src_info[ :wbuff ].bytesize >= PROXY_CHUNK_SIZE
        spring = src_info[ :chunks ].size > 0 ? ( src_info[ :spring ] + 1 ) : 0
        filename = "#{ Process.pid }-#{ Addrinfo.new( src_info[ :src_addr ] ).ip_unpack.join( '-' ) }.#{ spring }"
        chunk_path = File.join( @src_chunk_dir, filename )

        begin
          IO.binwrite( chunk_path, src_info[ :wbuff ] )
        rescue Errno::ENOSPC => e
          puts "p#{ Process.pid } #{ Time.new } #{ e.class }, close src"
          set_is_closing( src )
          return
        end

        src_info[ :chunks ] << filename
        src_info[ :spring ] = spring
        src_info[ :wbuff ].clear
      end

      add_write( src )
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data

      if dst_info[ :wbuff ].bytesize >= PROXY_CHUNK_SIZE
        spring = dst_info[ :chunks ].size > 0 ? ( dst_info[ :spring ] + 1 ) : 0
        filename = "#{ Process.pid }-#{ dst_info[ :local_port ] }.#{ spring }"
        chunk_path = File.join( @dst_chunk_dir, filename )

        begin
          IO.binwrite( chunk_path, dst_info[ :wbuff ] )
        rescue Errno::ENOSPC => e
          puts "p#{ Process.pid } #{ Time.new } #{ e.class }, close dst"
          set_is_closing( dst )
          return
        end

        dst_info[ :chunks ] << filename
        dst_info[ :spring ] = spring
        dst_info[ :wbuff ].clear
      end

      add_write( dst )
    end

    ##
    # add read
    #
    def add_read( sock, role )
      unless @reads.include?( sock )
        @reads << sock
      end

      @roles[ sock ] = role
    end

    ##
    # add write
    #
    def add_write( sock )
      unless @writes.include?( sock )
        @writes << sock
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
    # close src
    #
    def close_src( src )
      # puts "debug1 close src"
      close_sock( src )
      src_info = @src_infos.delete( src )

      src_info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( @src_chunk_dir, filename ) )
        rescue Errno::ENOENT
        end
      end

      src_addr = src_info[ :src_addr ]

      if src_info[ :proxy_type ] == :tunnel
        return if @tun.closed?

        src_ext = @tun_info[ :src_exts ][ src_addr ]
        return if src_ext.nil? || src_ext[ :dst_port ].nil?

        if src_ext[ :is_dst_closed ]
          # puts "debug1 2-2. after close src -> dst closed ? yes -> del src ext -> send fin2"
          del_src_ext( src_addr )
          data = [ [ 0, FIN2 ].pack( 'Q>C' ), src_addr ].join
          add_tun_ctlmsg( data )
        else
          # puts "debug1 1-1. after close src -> dst closed ? no -> send fin1"
          data = [ [ 0, FIN1 ].pack( 'Q>C' ), src_addr, [ src_ext[ :biggest_pack_id ], src_ext[ :continue_dst_pack_id ] ].pack( 'Q>Q>' ) ].join
          add_tun_ctlmsg( data )
        end
      elsif src_info[ :proxy_type ] == :direct
        set_is_closing( src_info[ :dst ] )
      end
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )

      dst_info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( @dst_chunk_dir, filename ) )
        rescue Errno::ENOENT
        end
      end

      @dsts.delete( dst_info[ :local_port ] )
      set_is_closing( dst_info[ :src ] )
    end

    ##
    # close tun
    #
    def close_tun( tun )
      # puts "debug1 close tun"
      close_sock( tun )

      @tun_info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( @tun_chunk_dir, filename ) )
        rescue Errno::ENOENT
        end
      end

      @tun_info[ :src_exts ].each{ | _, src_ext | set_is_closing( src_ext[ :src ] ) }
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
    def del_src_ext( src_addr )
      src_ext = @tun_info[ :src_exts ].delete( src_addr )

      if src_ext
        @tun_info[ :src_addrs ].delete( src_ext[ :dst_port ] )
      end
    end

    ##
    # release wmems
    #
    def release_wmems( src_ext, completed_pack_id )
      if completed_pack_id > src_ext[ :completed_pack_id ]
        # puts "debug2 update completed pack #{ completed_pack_id }"
        pack_ids = src_ext[ :wmems ].keys.select { | pack_id | pack_id <= completed_pack_id }

        pack_ids.each do | pack_id |
          src_ext[ :wmems ].delete( pack_id )
          src_ext[ :send_ats ].delete( pack_id )
        end

        src_ext[ :completed_pack_id ] = completed_pack_id
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
      data = src_info[ :cache ]
      from = :cache

      if data.empty?
        if src_info[ :chunks ].any?
          path = File.join( @src_chunk_dir, src_info[ :chunks ].shift )

          begin
            src_info[ :cache ] = data = IO.binread( path )
            File.delete( path )
          rescue Errno::ENOENT => e
            puts "p#{ Process.pid } #{ Time.new } read #{ path } #{ e.class }"
            close_src( src )
            return
          end
        else
          data = src_info[ :wbuff ]
          from = :wbuff
        end
      end

      if data.empty?
        if src_info[ :is_closing ]
          close_src( src )
        else
          @writes.delete( src )
        end

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
      src_info[ from ] = data
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]
      data = dst_info[ :cache ]
      from = :cache

      if data.empty?
        if dst_info[ :chunks ].any?
          path = File.join( @dst_chunk_dir, dst_info[ :chunks ].shift )

          begin
            dst_info[ :cache ] = data = IO.binread( path )
            File.delete( path )
          rescue Errno::ENOENT => e
            puts "p#{ Process.pid } #{ Time.new } read #{ path } #{ e.class }"
            close_dst( dst )
            return
          end
        else
          data = dst_info[ :wbuff ]
          from = :wbuff
        end
      end

      if data.empty?
        if dst_info[ :is_closing ]
          close_dst( dst )
        else
          @writes.delete( dst )
        end

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
      dst_info[ from ] = data
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if @tun_info[ :is_closing ]
        close_tun( tun )
        return
      end

      now = Time.new

      # 传ctlmsg
      while @tun_info[ :ctlmsgs ].any?
        to_addr, data = @tun_info[ :ctlmsgs ].first

        begin
          tun.sendmsg( data, 0, to_addr )
        rescue IO::WaitWritable, Errno::EINTR
          return
        end

        @tun_info[ :ctlmsgs ].shift
      end

      # 重传
      while @tun_info[ :resendings ].any?
        src_addr, pack_id = @tun_info[ :resendings ].first
        src_ext = @tun_info[ :src_exts ][ src_addr ]

        if src_ext
          data = src_ext[ :wmems ][ pack_id ]

          if data
            begin
              tun.sendmsg( data, 0, @tun_info[ :tund_addr ] )
            rescue IO::WaitWritable, Errno::EINTR
              return
            end
          end
        end

        @tun_info[ :resendings ].shift
        return
      end

      # 若写后达到上限，暂停取写前
      if @tun_info[ :src_exts ].map{ | _, src_ext | src_ext[ :wmems ].size }.sum >= WMEMS_LIMIT
        unless @tun_info[ :paused ]
          puts "p#{ Process.pid } #{ Time.new } pause tun"
          @tun_info[ :paused ] = true
        end

        @writes.delete( tun )
        return
      end

      # 取写前
      if @tun_info[ :caches ].any?
        src_addr, data = @tun_info[ :caches ].first
        from = :caches
      elsif @tun_info[ :chunks ].any?
        path = File.join( @tun_chunk_dir, @tun_info[ :chunks ].shift )

        begin
          data = IO.binread( path )
          File.delete( path )
        rescue Errno::ENOENT => e
          puts "p#{ Process.pid } #{ Time.new } read #{ path } #{ e.class }"
          close_tun( tun )
          return
        end

        caches = []

        until data.empty?
          _src_addr = data[ 0, 16 ]
          pack_size = data[ 16, 2 ].unpack( 'n' ).first
          caches << [ _src_addr, data[ 18, pack_size ] ]
          data = data[ ( 18 + pack_size )..-1 ]
        end

        @tun_info[ :caches ] = caches
        src_addr, data = caches.first
        from = :caches
      elsif @tun_info[ :wbuffs ].any?
        src_addr, data = @tun_info[ :wbuffs ].first
        from = :wbuffs
      else
        @writes.delete( tun )
        return
      end

      src_ext = @tun_info[ :src_exts ][ src_addr ]

      if src_ext
        pack_id = src_ext[ :biggest_pack_id ] + 1

        if pack_id <= CONFUSE_UNTIL
          data = @custom.encode( data )
          # puts "debug1 encoded pack #{ pack_id }"
        end

        data = [ [ pack_id ].pack( 'Q>' ), src_addr, data ].join

        begin
          tun.sendmsg( data, 0, @tun_info[ :tund_addr ] )
        rescue IO::WaitWritable, Errno::EINTR
          return
        end

        # puts "debug2 written pack #{ pack_id }"
        src_ext[ :biggest_pack_id ] = pack_id
        src_ext[ :wmems ][ pack_id ] = data
        src_ext[ :send_ats ][ pack_id ] = now
        src_ext[ :last_continue_at ] = now
      end

      @tun_info[ from ].shift
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

      # puts "debug1 accept a src #{ addrinfo.inspect }"
      src_addr = addrinfo.to_sockaddr
      @src_infos[ src ] = {
        src_addr: src_addr,      # src地址
        proxy_proto: :uncheck,   # :uncheck / :http / :socks5
        proxy_type: :uncheck,    # :uncheck / :checking / :direct / :tunnel / :negotiation
        dst: nil,                # :direct的场合，对应的dst
        destination_domain: nil, # 目的地域名
        destination_port: nil,   # 目的地端口
        rbuffs: [],              # 非CONNECT，dst或者远端dst未准备好，暂存流量
        wbuff: '',               # 写前
        cache: '',               # 块读出缓存
        chunks: [],              # 块队列，写前达到块大小时结一个块 filename
        spring: 0,               # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        created_at: Time.new,    # 创建时间
        last_recv_at: nil,       # 上一次收到流量的时间，过期关闭
        is_closing: false        # 是否准备关闭
      }

      add_read( src, :src )
    end

    ##
    # read src
    #
    def read_src( src )
      begin
        data = src.read_nonblock( PROXY_PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 read src #{ e.class }"
        set_is_closing( src )
        return
      end

      # puts "debug2 read src #{ data.inspect }"
      src_info = @src_infos[ src ]
      src_info[ :last_recv_at ] = Time.new
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck
        if data[ 0, 7 ] == 'CONNECT'
          # puts "debug1 CONNECT"
          domain_and_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]
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

          data, domain_and_port = sub_http_request( data )

          unless domain_and_port
            # puts "debug1 not HTTP"
            domain_and_port = host_line.split( ' ' )[ 1 ]
          end

          src_info[ :rbuffs ] << data
        end

        domain, port = domain_and_port.split( ':' )
        port = port ? port.to_i : 80

        src_info[ :proxy_proto ] = :http
        src_info[ :destination_domain ] = domain
        src_info[ :destination_port ] = port

        resolve_domain( src, domain )
      when :checking
        # puts "debug1 add src rbuff while checking #{ data.inspect }"
        src_info[ :rbuffs ] << data
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
            deal_with_destination_ip( src, destination_ip )
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
        src_addr = src_info[ :src_addr ]
        src_ext = @tun_info[ :src_exts ][ src_addr ]

        unless src_ext
          # puts "debug1 not found src ext"
          set_is_closing( src )
          return
        end

        if src_ext[ :dst_port ]
          if @tun.closed?
            # puts "debug1 tun closed, close src"
            set_is_closing( src )
            return
          end

          if src_info[ :rbuffs ].any?
            data, _ = sub_http_request( data )
          end

          add_tun_wbuff( src_addr, data )
        else
          # puts "debug1 remote dst not ready, save data to src rbuff"
          src_info[ :rbuffs ] << data
        end
      when :direct
        dst = src_info[ :dst ]

        if dst
          if dst.closed?
            # puts "debug1 dst closed, close src"
            set_is_closing( src )
            return
          end

          if src_info[ :rbuffs ].any?
            data, _ = sub_http_request( data )
          end

          add_dst_wbuff( dst, data )
        else
          # puts "debug1 dst not ready, save data to src rbuff"
          src_info[ :rbuffs ] << data
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
      begin
        data = dst.read_nonblock( PROXY_PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        set_is_closing( dst )
        return
      end

      # puts "debug2 read dst #{ data.inspect }"
      dst_info = @dst_infos[ dst ]
      dst_info[ :last_recv_at ] = Time.new
      src = dst_info[ :src ]

      if src.closed?
        puts "p#{ Process.pid } #{ Time.new } src closed, close dst"
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
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if pack_id == 0
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when TUND_PORT
          return if ( from_addr != @proxyd_addr ) || @tun_info[ :tund_addr ]

          @tun_info[ :last_recv_at ] = now
          tund_port = data[ 9, 2 ].unpack( 'n' ).first

          # puts "debug1 got tund port #{ tund_port }"
          tund_addr = Socket.sockaddr_in( tund_port, @proxyd_host )
          @tun_info[ :tund_addr ] = tund_addr

          if @tun_info[ :ctlmsg_rbuffs ].any?
            # puts "debug1 move #{ @tun_info[ :ctlmsg_rbuffs ].size } ctlmsg rbuffs to ctlmsgs"
            @tun_info[ :ctlmsgs ] += @tun_info[ :ctlmsg_rbuffs ].map{ | _data | [ tund_addr, _data ] }
            @tun_info[ :ctlmsg_rbuffs ].clear
            add_write( tun )
          end
        when PAIRED
          return if from_addr != @tun_info[ :tund_addr ]

          src_addr = data[ 9, 16 ]
          dst_port = data[ 25, 2 ].unpack( 'n' ).first

          src_ext = @tun_info[ :src_exts ][ src_addr ]
          return if src_ext.nil? || src_ext[ :dst_port ]

          src = src_ext[ :src ]
          return if src.closed?

          @tun_info[ :last_recv_at ] = now

          # puts "debug1 got paired #{ Addrinfo.new( src_addr ).inspect } #{ dst_port }"

          if dst_port == 0
            set_is_closing( src )
            return
          end

          src_ext[ :dst_port ] = dst_port
          @tun_info[ :src_addrs ][ dst_port ] = src_addr

          src_info = @src_infos[ src ]

          if src_info[ :proxy_proto ] == :http
            datas = src_info[ :rbuffs ]

            if datas.empty?
              # CONNECT
              # puts "debug1 add src wbuff http ok"
              add_src_wbuff( src, HTTP_OK )
            else
              # not CONNECT
              # puts "debug1 add src rbuffs to tun wbuffs"

              datas.each do | _data |
                add_tun_wbuff( src_addr, _data )
              end
            end
          elsif src_info[ :proxy_proto ] == :socks5
            add_src_wbuff_socks5_conn_reply( src_ext[ :src ] )
          end
        when DEST_STATUS
          return if from_addr != @tun_info[ :tund_addr ]

          dst_port, biggest_dst_pack_id, continue_src_pack_id = data[ 9, 18 ].unpack( 'nQ>Q>' )

          src_addr = @tun_info[ :src_addrs ][ dst_port ]
          return unless src_addr

          src_ext = @tun_info[ :src_exts ][ src_addr ]
          return unless src_ext

          # puts "debug2 got dest status"
          @tun_info[ :last_recv_at ] = now

          # 更新对面发到几
          if biggest_dst_pack_id > src_ext[ :biggest_dst_pack_id ]
            # puts "debug2 update biggest dst pack #{ biggest_dst_pack_id }"
            src_ext[ :biggest_dst_pack_id ] = biggest_dst_pack_id

            # 接到对面状态，若对面已关闭，且最后一个包已经进写前，关闭src
            if src_ext[ :is_dst_closed ] && ( biggest_dst_pack_id == src_ext[ :continue_dst_pack_id ] )
              # puts "debug1 2-1. recv traffic/fin1/dst status -> dst closed and all traffic received ? -> close src after write"
              set_is_closing( src_ext[ :src ] )
            end
          end

          release_wmems( src_ext, continue_src_pack_id )

          # 发miss
          if !src_ext[ :src ].closed? && ( src_ext[ :continue_dst_pack_id ] < src_ext[ :biggest_dst_pack_id ] )
            ranges = []
            curr_pack_id = src_ext[ :continue_dst_pack_id ] + 1

            src_ext[ :pieces ].keys.sort.each do | pack_id |
              if pack_id > curr_pack_id
                ranges << [ curr_pack_id, pack_id - 1 ]
              end

              curr_pack_id = pack_id + 1
            end

            if curr_pack_id <= src_ext[ :biggest_dst_pack_id ]
              ranges << [ curr_pack_id, src_ext[ :biggest_dst_pack_id ] ]
            end

            pack_count = 0
            # puts "debug1 continue/biggest #{ src_ext[ :continue_dst_pack_id ] }/#{ src_ext[ :biggest_dst_pack_id ] } send MISS #{ ranges.size }"

            ranges.each do | pack_id_begin, pack_id_end |
              if pack_count >= BREAK_SEND_MISS
                puts "p#{ Process.pid } #{ Time.new } break send miss at #{ pack_id_begin }"
                break
              end

              data2 = [ 0, MISS, dst_port, pack_id_begin, pack_id_end ].pack( 'Q>CnQ>Q>' )
              add_tun_ctlmsg( data2 )
              pack_count += ( pack_id_end - pack_id_begin + 1 )
            end
          end
        when MISS
          return if from_addr != @tun_info[ :tund_addr ]

          src_addr = data[ 9, 16 ]
          pack_id_begin, pack_id_end = data[ 25, 16 ].unpack( 'Q>Q>' )

          src_ext = @tun_info[ :src_exts ][ src_addr ]
          return unless src_ext

          @tun_info[ :last_recv_at ] = now

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            send_at = src_ext[ :send_ats ][ pack_id ]

            if send_at
              break if now - send_at < STATUS_INTERVAL
              @tun_info[ :resendings ] << [ src_addr, pack_id ]
            end
          end

          add_write( tun )
        when FIN1
          return if from_addr != @tun_info[ :tund_addr ]

          dst_port, biggest_dst_pack_id, continue_src_pack_id = data[ 9, 18 ].unpack( 'nQ>Q>' )

          src_addr = @tun_info[ :src_addrs ][ dst_port ]
          return unless src_addr

          src_ext = @tun_info[ :src_exts ][ src_addr ]
          return unless src_ext

          @tun_info[ :last_recv_at ] = now

          # puts "debug1 got fin1 #{ dst_port } biggest dst pack #{ biggest_dst_pack_id } completed src pack #{ continue_src_pack_id }"
          src_ext[ :is_dst_closed ] = true
          src_ext[ :biggest_dst_pack_id ] = biggest_dst_pack_id
          release_wmems( src_ext, continue_src_pack_id )

          # 接到对面已关闭，若最后一个包已经进写前，关闭src
          if ( biggest_dst_pack_id == src_ext[ :continue_dst_pack_id ] )
            # puts "debug1 2-1. recv fin1 -> set dst closed -> all traffic received ? -> close src after write"
            set_is_closing( src_ext[ :src ] )
          end
        when FIN2
          return if from_addr != @tun_info[ :tund_addr ]

          dst_port = data[ 9, 2 ].unpack( 'n' ).first

          src_addr = @tun_info[ :src_addrs ][ dst_port ]
          return unless src_addr

          @tun_info[ :last_recv_at ] = now

          # puts "debug1 1-2. recv fin2 -> del src ext"
          del_src_ext( src_addr )
        when TUND_FIN
          return if from_addr != @tun_info[ :tund_addr ]

          @tun_info[ :last_recv_at ] = now

          puts "p#{ Process.pid } #{ Time.new } recv tund fin"
          set_is_closing( tun )
        end

        return
      end

      return if from_addr != @tun_info[ :tund_addr ]

      dst_port = data[ 8, 2 ].unpack( 'n' ).first

      src_addr = @tun_info[ :src_addrs ][ dst_port ]
      return unless src_addr

      src_ext = @tun_info[ :src_exts ][ src_addr ]
      return if src_ext.nil? || src_ext[ :src ].closed?
      return if ( pack_id <= src_ext[ :continue_dst_pack_id ] ) || src_ext[ :pieces ].include?( pack_id )

      @tun_info[ :last_recv_at ] = now

      data = data[ 10..-1 ]
      # puts "debug2 got pack #{ pack_id }"

      if pack_id <= CONFUSE_UNTIL
        # puts "debug2 #{ data.inspect }"
        data = @custom.decode( data )
        # puts "debug1 decoded pack #{ pack_id }"
      end

      # 放进写前，跳号放碎片缓存
      if pack_id - src_ext[ :continue_dst_pack_id ] == 1
        while src_ext[ :pieces ].include?( pack_id + 1 )
          data << src_ext[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        src_ext[ :continue_dst_pack_id ] = pack_id
        src_ext[ :last_continue_at ] = now
        add_src_wbuff( src_ext[ :src ], data )
        # puts "debug2 update continue dst pack #{ pack_id }"

        # 接到流量，若对面已关闭，且流量正好收全，关闭src
        if src_ext[ :is_dst_closed ] && ( pack_id == src_ext[ :biggest_dst_pack_id ] )
          # puts "debug1 2-1. recv traffic/fin1/dst status -> dst closed and all traffic received ? -> close src after write"
          set_is_closing( src_ext[ :src ] )
        end
      else
        src_ext[ :pieces ][ pack_id ] = data
      end
    end

  end
end
