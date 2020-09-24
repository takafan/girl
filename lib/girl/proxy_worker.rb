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
          # 先写，再读
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
                set_is_closing( @tun )
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
                  set_is_closing( src )
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

              if @tun_info[ :srcs ].any? then
                @tun_info[ :srcs ].each do | _, src |
                  src_info = @src_infos[ src ]

                  if src_info && src_info[ :dst_id ] then
                    # 距上一次收到中转半秒以内，发continue recv（收到的连续的最后一个包号，以及后面有没有跳号包）；发multi piece（跳号包号）。
                    if src_info[ :last_recv_at ] && ( now - src_info[ :last_recv_at ] < CHECK_STATUS_INTERVAL ) then
                      has_piece = src_info[ :pieces ].any?
                      data = [ 0, CONTINUE_RECV, src_info[ :dst_id ], src_info[ :continue_recv_pack_id ], ( has_piece ? 1 : 0 ) ].pack( 'Q>CnQ>C' )
                      break unless send_data( @tun, data, @tun_info[ :tund_addr ] )

                      if has_piece then
                        ranges = []
                        piece_ids = src_info[ :pieces ].keys.sort
                        begin_pack_id = end_pack_id = piece_ids[ 0 ]

                        piece_ids[ 1..-1 ].each do | pack_id |
                          if end_pack_id + 1 == pack_id then
                            end_pack_id = pack_id
                          else
                            ranges << [ begin_pack_id, end_pack_id ]
                            begin_pack_id = end_pack_id = pack_id
                          end
                        end

                        ranges << [ begin_pack_id, end_pack_id ]

                        # puts "debug1 send multi piece #{ ranges.size }"
                        idx = 0

                        while idx < ranges.size
                          chunk = ranges[ idx, MULTI_PIECE_SIZE ].map{ | b, e | [ b, e ].pack( 'Q>Q>' ) }.join
                          data = [ [ 0, MULTI_PIECE, src_info[ :dst_id ] ].pack( 'Q>Cn' ), chunk ].join
                          break unless send_data( @tun, data, @tun_info[ :tund_addr ] )
                          idx += MULTI_PIECE_SIZE
                        end
                      end
                    end

                    # 距上一次发出中转超过半秒，处理multi piece（删对应写后，重传剩余写后，删multi piece）。
                    if src_info[ :last_sent_at ] && ( now - src_info[ :last_sent_at ] >= CHECK_STATUS_INTERVAL ) && src_info[ :arrived_ranges ].any? then
                      ranges = src_info[ :arrived_ranges ]
                      idx = 0

                      while idx < ranges.size
                        pack_id_begin, pack_id_end = ranges[ idx ], ranges[ idx + 1 ]

                        ( pack_id_begin..pack_id_end ).each do | pack_id |
                          @tun_info[ :wmems ].delete( [ src_info[ :id ], pack_id ] )
                        end

                        idx += 2
                      end

                      wmems = @tun_info[ :wmems ].select{ | k, _ | k[ 0 ] == src_info[ :id ] }

                      if wmems.any? then
                        # puts "debug1 #{ Time.new } resend #{ datas.size }"

                        wmems.each do | _, v |
                          break unless send_data( @tun, v[ 0 ], @tun_info[ :tund_addr ] )
                        end
                      end

                      src_info[ :arrived_ranges ].clear
                    end
                  end
                end
              end

              # 恢复读
              if @tun_info[ :pause_srcs ].any? && ( @tun_info[ :wmems ].size < RESUME_BELOW ) then
                puts "p#{ Process.pid } #{ Time.new } resume srcs #{ @tun_info[ :pause_srcs ].size }"

                @tun_info[ :pause_srcs ].each do | src |
                  add_read( src )
                end

                @tun_info[ :pause_srcs ].clear
                next_tick
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
        SEND_HELLO_COUNT.times do | i |
          if @tun.closed? || @tun_info[ :tund_addr ] then
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
        port: port,           # 端口
        pending_sources: [],  # 还没配上tund，暂存的src
        wbuffs: [],           # 写前 [ src_id, pack_id, data ]
        wmems: {},            # 写后 [ src_id, pack_id ] => [ data, add_at ]
        tund_addr: nil,       # tund地址
        srcs: {},             # src_id => src
        src_ids: {},          # dst_id => src_id
        pause_srcs: [],       # 暂停的src
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间
        last_sent_at: nil,    # 上一次发出流量的时间
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

      if RUBY_PLATFORM.include?( 'linux' ) then
        dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      end

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable
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
        is_closing: false           # 是否准备关闭
      }

      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          # puts "debug1 add src wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        else
          # puts "debug1 add src rbuff to dst wbuff"
          add_dst_wbuff( dst, src_info[ :rbuff ] )
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
      if sock && !sock.closed? && !@reads.include?( sock ) then
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
      if sock && !sock.closed? && !@writes.include?( sock ) then
        @writes << sock
      end
    end

    ##
    # set is closing
    #
    def set_is_closing( sock )
      if sock && !sock.closed? then
        role = @roles[ sock ]
        # puts "debug1 set #{ role.to_s } is closing"

        case role
        when :src then
          src_info = @src_infos[ sock ]
          src_info[ :is_closing ] = true
        when :dst then
          dst_info = @dst_infos[ sock ]
          dst_info[ :is_closing ] = true
        when :tun then
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

        if pack_id <= CONFUSE_UNTIL then
          # puts "debug2 encode chunk #{ pack_id }\n#{ chunk.inspect }\n"
          chunk = @custom.encode( chunk )
        end

        data2 = [ [ pack_id, src_id ].pack( 'Q>Q>' ), chunk ].join
        break unless send_data( @tun, data2, @tun_info[ :tund_addr ] )
        @tun_info[ :wmems ][ [ src_id, pack_id ] ] = [ data2, now ]
        idx += PACK_SIZE
      end

      src_info[ :biggest_pack_id ] = pack_id
      src_info[ :last_sent_at ] = now

      # 写后超过上限，暂停读src
      if @tun_info[ :wmems ].size >= WMEMS_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause src #{ src_id } #{ src_info[ :destination_domain ] } #{ src_info[ :biggest_pack_id ] }"
        @reads.delete( src )

        unless @tun_info[ :pause_srcs ].include?( src ) then
          @tun_info[ :pause_srcs ] << src
        end
      end
    end

    ##
    # send data
    #
    def send_data( tun, data, to_addr )
      return false unless to_addr

      begin
        tun.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        puts "#{ Time.new } #{ e.class }, close tun"
        close_tun( tun )
        return false
      end

      @tun_info[ :last_sent_at ] = Time.new
      true
    end

    ##
    # del src ext
    #
    def del_src_ext( src )
      src_info = @src_infos.delete( src )

      if src_info then
        if src_info[ :dst_id ] then
          @tun_info[ :src_ids ].delete( src_info[ :dst_id ] )
        end

        @tun_info[ :wmems ].delete_if { | k, _ | k[ 0 ] == src_info[ :id ] }
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

      if src_info[ :proxy_type ] == :direct then
        @src_infos.delete( src )

        if src_info[ :dst ] then
          set_is_closing( src_info[ :dst ] )
        end

        return
      end

      if src_info[ :fin1_dst_pack_id ] then
        # puts "debug1 2-3. after close src -> dst closed ? yes -> del src ext -> send fin2"
        del_src_ext( src )
        data = [ 0, FIN2, src_info[ :id ] ].pack( 'Q>CQ>' )
      else
        # puts "debug1 1-1. after close src -> dst closed ? no -> send fin1"
        data = [ 0, FIN1, src_info[ :id ], src_info[ :biggest_pack_id ], src_info[ :continue_recv_pack_id ] ].pack( 'Q>CQ>Q>Q>' )
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

      if src_info[ :is_closing ] then
        close_src( src )
        return
      end

      data = src_info[ :wbuff ]

      if data.empty? then
        @writes.delete( src )
        return
      end

      begin
        written = src.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 write src #{ e.class }"
        close_src( src )
        return
      end

      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]

      if dst_info[ :is_closing ] then
        close_dst( dst )
        return
      end

      data = dst_info[ :wbuff ]

      if data.empty? then
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

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data

      unless dst_info[ :src ].closed? then
        src_info = @src_infos[ dst_info[ :src ] ]
        src_info[ :last_sent_at ] = Time.new
      end
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if @tun_info[ :is_closing ] then
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
        id: src_id,               # id
        proxy_proto: :uncheck,    # :uncheck / :http / :socks5
        proxy_type: :uncheck,     # :uncheck / :checking / :direct / :tunnel / :negotiation
        dst: nil,                 # :direct的场合，对应的dst
        destination_domain: nil,  # 目的地域名
        destination_port: nil,    # 目的地端口
        biggest_pack_id: 0,       # 最大包号码
        is_connect: true,         # 代理协议是http的场合，是否是CONNECT
        rbuff: '',                # 非CONNECT，dst或者远端dst未准备好，暂存流量
        wbuff: '',                # 写前
        dst_id: nil,              # 远端dst id
        continue_recv_pack_id: 0, # 收到的连续的最后一个包号
        pieces: {},               # 跳号包 dst_pack_id => data
        fin1_dst_pack_id: nil,    # 关闭的dst的最终包号码
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到中转（由dst收到，或者由tun收到）的时间
        last_sent_at: nil,        # 上一次发出中转（由dst发出，或者由tun发出）的时间
        arrived_ranges: [],       # 送达的包号区间
        is_closing: false         # 是否准备关闭
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

      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0, 7 ] == 'CONNECT' then
          # puts "debug1 CONNECT"
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port then
            puts "p#{ Process.pid } #{ Time.new } CONNECT miss domain"
            set_is_closing( src )
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

          unless host_line then
            # puts "debug1 not found host line"
            set_is_closing( src )
            return
          end

          data, domain_port = sub_http_request( data )

          unless domain_port then
            # puts "debug1 not HTTP"
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
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
      when :checking then
        # puts "debug1 add src rbuff while checking #{ data.inspect }"
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
          if @tun.closed?
            # puts "debug1 tun closed, close src"
            set_is_closing( src )
            return
          end

          unless src_info[ :is_connect ] then
            data, _ = sub_http_request( data )
          end

          tunnel_data( src, data )
        else
          # puts "debug1 remote dst not ready, save data to src rbuff"
          src_info[ :rbuff ] << data
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          if dst.closed? then
            # puts "debug1 dst closed, close src"
            set_is_closing( src )
            return
          end

          unless src_info[ :is_connect ] then
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

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]

      if src.closed? then
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

          src = @tun_info[ :srcs ][ src_id ]
          return if src.nil? || src.closed?

          src_info = @src_infos[ src ]
          return if src_info.nil? || src_info[ :dst_id ]

          # puts "debug1 got paired #{ src_id } #{ dst_id }"

          if dst_id == 0 then
            set_is_closing( src )
            return
          end

          src_info[ :dst_id ] = dst_id
          @tun_info[ :src_ids ][ dst_id ] = src_id

          if src_info[ :proxy_proto ] == :http then
            if src_info[ :is_connect ] then
              # puts "debug1 add src wbuff http ok"
              add_src_wbuff( src, HTTP_OK )
            else
              # puts "debug1 send src rbuff to tund"
              tunnel_data( src, src_info[ :rbuff ] )
            end
          elsif src_info[ :proxy_proto ] == :socks5 then
            add_src_wbuff_socks5_conn_reply( src )
          end
        when CONTINUE_RECV then
          # 收到continue recv，删multi piece；消写后到until pack id为止；
          # 若后面没跳号包，从写后里找出比until pack id大的，且发送已超过半秒的包，重传。（应对“恰好是最后n个包掉了”的情况）
          src_id, until_pack_id, has_piece = data[ 9, 17 ].unpack( 'Q>Q>C' )

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          src_info[ :arrived_ranges ].clear
          @tun_info[ :wmems ].delete_if { | k, _ | ( k[ 0 ] == src_id ) && ( k[ 1 ] <= until_pack_id ) }

          if has_piece == 0 then
            wmems = @tun_info[ :wmems ].select{ | k, v | ( k[ 0 ] == src_id ) && ( k[ 1 ] > until_pack_id ) && ( now - v[ 1 ] >= CHECK_STATUS_INTERVAL ) }

            if wmems.any? then
              # puts "debug1 resend tails #{ src_info[ :destination_domain ] } #{ wmems.size }"

              wmems.each do | _, v |
                break unless send_data( tun, v[ 0 ], @tun_info[ :tund_addr ] )
              end
            end
          end
        when MULTI_PIECE then
          # 收到multi piece，放着。
          src_id, *ranges = data[ 9..-1 ].unpack( 'Q>Q>*' )

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          return if ranges.empty? || ( ranges.size % 2 != 0 )

          src_info[ :arrived_ranges ] += ranges
          # puts "debug1 arrived ranges size #{ src_info[ :arrived_ranges ].size }"
        when FIN1 then
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id, fin1_dst_pack_id, continue_src_pack_id = data[ 9, 18 ].unpack( 'nQ>Q>' )

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          src = @tun_info[ :srcs ][ src_id ]
          return unless src

          src_info = @src_infos[ src ]
          return unless src_info

          # puts "debug1 got fin1 #{ dst_id } fin1 dst pack #{ fin1_dst_pack_id } completed src pack #{ continue_src_pack_id }"
          src_info[ :fin1_dst_pack_id ] = fin1_dst_pack_id

          if src_info[ :continue_recv_pack_id ] == fin1_dst_pack_id then
            # puts "debug1 2-1. tun recv fin1 -> all traffic received ? -> close src after write"
            set_is_closing( src )
          end
        when FIN2 then
          return if from_addr != @tun_info[ :tund_addr ]

          dst_id = data[ 9, 2 ].unpack( 'n' ).first

          src_id = @tun_info[ :src_ids ][ dst_id ]
          return unless src_id

          # puts "debug1 1-2. tun recv fin2 -> del src ext"
          src = @tun_info[ :srcs ][ src_id ]

          if src && src.closed? then
            del_src_ext( src )
          end
        when TUND_FIN then
          return if from_addr != @tun_info[ :tund_addr ]

          puts "p#{ Process.pid } #{ Time.new } recv tund fin"
          set_is_closing( tun )
        when IP_CHANGED then
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

      return if ( pack_id <= src_info[ :continue_recv_pack_id ] ) || src_info[ :pieces ].include?( pack_id )

      data = data[ 10..-1 ]

      if pack_id <= CONFUSE_UNTIL then
        data = @custom.decode( data )
        # puts "debug2 decoded pack #{ pack_id }\n#{ data.inspect }\n"
      end

      # 放进写前，跳号放碎片缓存，发确认
      if pack_id - src_info[ :continue_recv_pack_id ] == 1 then
        while src_info[ :pieces ].include?( pack_id + 1 )
          data << src_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        src_info[ :continue_recv_pack_id ] = pack_id
        add_src_wbuff( src, data )

        # 若对面已关闭，且流量正好收全，关闭src
        if src_info[ :fin1_dst_pack_id ] == pack_id then
          # puts "debug1 2-2. tun recv traffic -> dst closed and all traffic received ? -> close src after write"
          set_is_closing( src )
        end
      else
        src_info[ :pieces ][ pack_id ] = data
        src_info[ :last_recv_at ] = now
      end
    end

  end
end
