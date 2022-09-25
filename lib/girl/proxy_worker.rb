module Girl
  class ProxyWorker

    ##
    # initialize
    #
    def initialize( redir_port, proxyd_host, proxyd_port, directs, remotes, nameserver, im )
      @proxyd_host = proxyd_host
      @proxyd_port = proxyd_port
      @directs = directs
      @remotes = remotes
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @im = im
      @custom = Girl::ProxyCustom.new( im )
      @reads = []
      @writes = []
      @roles = {}            # sock => :redir / :infod / :tcp / :src / :dst / :tun / :dns
      @resolv_caches = {}    # domain => [ ip, created_at ]
      @is_direct_caches = {} # ip => true / false
      @tcp_infos = {}        # tcp => { :rbuff, :wbuff, :created_at, :last_recv_at }
      @src_infos = {}        # src => { :src_id, :addrinfo, :proxy_proto, :proxy_type, :destination_domain, :destination_port,
                             #          :is_connect, :rbuff, :dst, :dst_id, :tcp, :tun,
                             #          :wbuff, :closing_write, :paused }
      @dst_infos = {}        # dst => { :dst_id, :src, :domain, :wbuff, :created_at, :connected, :last_add_wbuff_at, :closing_write, :paused }
      @tun_infos = {}        # tun => { :tun_id, :src, :domain, :wbuff, :created_at, :pong, :last_add_wbuff_at, :paused }
      @dns_infos = {}        # dns => { :dns_id, :domain, :src }
      @local_addrinfos = Socket.ip_address_list
      @tund_addrs = nil

      new_a_redir( redir_port )
      new_a_infod( redir_port )
      new_the_tcp
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :redir then
            read_redir( sock )
          when :infod then
            read_infod( sock )
          when :dns then
            read_dns( sock )
          when :tcp then
            read_tcp( sock )
          when :src then
            read_src( sock )
          when :dst then
            read_dst( sock )
          when :tun then
            read_tun( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :tcp then
            write_tcp( sock )
          when :src then
            write_src( sock )
          when :dst then
            write_dst( sock )
          when :tun then
            write_tun( sock )
          else
            puts "#{ Time.new } write unknown role #{ role }"
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
    # add a new source
    #
    def add_a_new_source( src )
      src_info = @src_infos[ src ]
      src_id = src_info[ :src_id ]
      destination_domain = src_info[ :destination_domain ]
      destination_port = src_info[ :destination_port ]
      domain_port = [ destination_domain, destination_port ].join( ':' )
      puts "#{ Time.new } add a new source #{ src_id } #{ domain_port }"
      data = "#{ [ A_NEW_SOURCE, src_id ].pack( 'CQ>' ) }#{ domain_port }"
      add_tcp_wbuff( pack_a_chunk( data ) )

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-src-paired',
          src_id: src_id
        }

        send_msg_to_infod( msg )
      end
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      dst_info[ :last_add_wbuff_at ] = Time.new
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = dst_info[ :src ]

        if src && !src.closed? then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause direct src #{ src_info[ :destination_domain ].inspect }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end
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
      # puts "debug add src.wbuff socks5 conn reply #{ data.inspect }"
      add_src_wbuff( src, data )
    end

    ##
    # add src rbuff
    #
    def add_src_rbuff( src, data )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        puts "#{ Time.new } src rbuff full"
        close_src( src )
      end
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      add_write( src )

      if src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :domain ].inspect }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        else
          tun = src_info[ :tun ]

          if tun then
            tun_info = @tun_infos[ tun ]

            if tun_info then
              puts "#{ Time.new } pause tun #{ tun_info[ :domain ].inspect }"
              @reads.delete( tun )
              tun_info[ :paused ] = true
            end
          end
        end
      end
    end

    ##
    # add tcp wbuff
    #
    def add_tcp_wbuff( data )
      return if @tcp.nil? || @tcp.closed?
      tcp_info = @tcp_infos[ @tcp ]
      tcp_info[ :wbuff ] << data
      add_write( @tcp )
    end

    ##
    # add tun wbuff
    #
    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      tun_info[ :last_add_wbuff_at ] = Time.new
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = tun_info[ :src ]

        if src && !src.closed? then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause remote src #{ src_info[ :destination_domain ].inspect }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
    end

    ##
    # close dns
    #
    def close_dns( dns )
      return if dns.nil? || dns.closed?
      # puts "debug close dns"
      close_sock( dns )
      @dns_infos.delete( dns )
      # puts "debug dns infos size #{ @dns_infos.size }"
    end

    ##
    # close dst
    #
    def close_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      # puts "debug dst infos size #{ @dst_infos.size }"

      if dst_info then
        close_src( dst_info[ :src ] )
      end
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @writes.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
        # puts "debug dst infos size #{ @dst_infos.size }"
      end
    end

    ##
    # close read src
    #
    def close_read_src( src )
      return if src.nil? || src.closed?
      # puts "debug close read src"
      src.close_read
      @reads.delete( src )
      src_info = @src_infos[ src ]

      if src_info[ :tun ] then
        data = "#{ [ SOURCE_CLOSED_READ, src_info[ :src_id ] ].pack( 'CQ>' ) }"
        add_tcp_wbuff( pack_a_chunk( data ) )
      end

      if src.closed? then
        # puts "debug src closed"
        @writes.delete( src )
        @roles.delete( src )
        @src_infos.delete( src )
        # puts "debug src infos size #{ @src_infos.size }"
      end
    end

    ##
    # close read tun
    #
    def close_read_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close read tun"
      tun.close_read
      @reads.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @writes.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
        # puts "debug tun infos size #{ @tun_infos.size }"
      end
    end

    ##
    # close sock
    #
    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    ##
    # close src
    #
    def close_src( src )
      return if src.nil? || src.closed?
      # puts "debug close src"
      close_sock( src )
      src_info = @src_infos.delete( src )
      # puts "debug src infos size #{ @src_infos.size }"

      if src_info then
        dst = src_info[ :dst ]

        if dst then
          close_dst( dst )
        elsif src_info[ :tun ] then
          close_tun( src_info[ :tun ] )
          data = "#{ [ SOURCE_CLOSED, src_info[ :src_id ] ].pack( 'CQ>' ) }#{ @im }"
          add_tcp_wbuff( pack_a_chunk( data ) )
        end
      end
    end

    ##
    # close tcp
    #
    def close_tcp( tcp )
      return if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      @tcp_infos.delete( tcp )
      new_the_tcp
    end

    ##
    # close tun
    #
    def close_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      tun_info = @tun_infos.delete( tun )
      # puts "debug tun infos size #{ @tun_infos.size }"

      if tun_info then
        close_src( tun_info[ :src ] )
      end
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @reads.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
        # puts "debug dst infos size #{ @dst_infos.size }"
      end
    end

    ##
    # close write src
    #
    def close_write_src( src )
      return if src.nil? || src.closed?
      # puts "debug close write src"
      src.close_write
      @writes.delete( src )
      src_info = @src_infos[ src ]

      if src_info[ :tun ] then
        data = "#{ [ SOURCE_CLOSED_WRITE, src_info[ :src_id ] ].pack( 'CQ>' ) }#{ @im }"
        add_tcp_wbuff( pack_a_chunk( data ) )
      end

      if src.closed? then
        # puts "debug src closed"
        @reads.delete( src )
        @roles.delete( src )
        @src_infos.delete( src )
        # puts "debug src infos size #{ @src_infos.size }"
      end
    end

    ##
    # close write tun
    #
    def close_write_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close write tun"
      tun.close_write
      @writes.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @reads.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
        # puts "debug tun infos size #{ @tun_infos.size }"
      end
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          msg = {
            message_type: 'check-expire'
          }

          send_msg_to_infod( msg )
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( ipaddr, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]
      ip = ipaddr.to_s
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst = Socket.new( ipaddr.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ e.class } #{ domain.inspect } #{ ip } #{ port }"
        close_src( src )
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } dst connect destination #{ e.class } #{ domain.inspect } #{ ip } #{ port }"
        dst.close
        close_src( src )
        return
      end

      dst_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug a new dst #{ dst.local_address.inspect } #{ dst_id }"

      dst_info = {
        dst_id: dst_id,         # dst id
        src: src,               # 对应src
        domain: domain,         # 目的地
        wbuff: '',              # 写前
        created_at: Time.new,   # 创建时间
        connected: false,       # 是否已连接
        last_add_wbuff_at: nil, # 上一次加写前的时间
        closing_write: false,   # 准备关闭写
        paused: false           # 是否已暂停
      }

      @dst_infos[ dst ] = dst_info
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          # puts "debug add src wbuff http ok"
          add_src_wbuff( src, HTTP_OK )
        elsif src_info[ :rbuff ] then
          # puts "debug move src rbuff to dst wbuff"
          dst_info[ :wbuff ] << src_info[ :rbuff ]
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_socks5_conn_reply( src )
      end

      add_read( dst, :dst )
      add_write( dst )

      Thread.new do
        sleep EXPIRE_CONNECTING

        msg = {
          message_type: 'check-dst-connected',
          dst_id: dst_id
        }

        send_msg_to_infod( msg )
      end
    end

    ##
    # new a infod
    #
    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      infod.bind( infod_addr )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    ##
    # new a redir
    #
    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 127 )
      puts "#{ Time.new } redir listen on #{ redir_port }"
      add_read( redir, :redir )
      @redir_port = redir_port
      @redir_local_address = redir.local_address
    end

    ##
    # new a remote
    #
    def new_a_remote( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :remote
      add_a_new_source( src )
    end

    ##
    # new a tun
    #
    def new_a_tun( src_id, dst_id )
      return unless @tund_addrs
      src, src_info = @src_infos.find{ | _, info | ( info[ :src_id ] == src_id ) && info[ :dst_id ].nil? }
      return if src.nil? || src.closed?
      src_info[ :dst_id ] = dst_id
      tund_addr = @tund_addrs.sample
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        tun.connect_nonblock( tund_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect tund #{ e.class }"
        tun.close
        close_src( src )
        return
      end

      domain = src_info[ :destination_domain ]
      tun_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug new a tun #{ tun_id } #{ Addrinfo.new( tund_addr ).inspect } #{ domain }"

      tun_info = {
        tun_id: tun_id,                 # tun id
        src: src,                       # 对应src
        domain: domain,                 # 目的地
        wbuff: [ dst_id ].pack( 'Q>' ), # 写前
        created_at: Time.new,           # 创建时间
        pong: false,                    # 是否有回应
        last_add_wbuff_at: nil,         # 上一次加写前的时间
        paused: false                   # 是否已暂停
      }

      @tun_infos[ tun ] = tun_info
      src_info[ :tun ] = tun
      add_read( tun, :tun )
      add_write( tun )

      Thread.new do
        sleep PING_TIMEOUT

        msg = {
          message_type: 'check-tun-pong',
          tun_id: tun_id
        }

        send_msg_to_infod( msg )
      end
    end

    ##
    # new a tunnel
    #
    def new_a_tunnel( ipaddr, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      ip = ipaddr.to_s
      port = src_info[ :destination_port ]

      if ( @local_addrinfos.any?{ | _addrinfo | _addrinfo.ip_address == ip } ) && ( port == @redir_port ) then
        puts "#{ Time.new } ignore #{ ip }:#{ port }"
        close_src( src )
        return
      end

      if ( src_info[ :destination_domain ] == @proxyd_host ) && ![ 80, 443 ].include?( port ) then
        # 访问远端非80/443端口，直连
        puts "#{ Time.new } direct #{ ip } #{ port }"
        new_a_dst( ipaddr, src )
        return
      end

      if @is_direct_caches.include?( ip ) then
        is_direct = @is_direct_caches[ ip ]
      else
        is_direct = @directs.any?{ | direct | direct.include?( ip ) }
        puts "#{ Time.new } cache is direct #{ src_info[ :destination_domain ] } #{ ip } #{ is_direct }"
        @is_direct_caches[ ip ] = is_direct
      end

      if is_direct then
        # puts "debug hit directs #{ ip }"
        new_a_dst( ipaddr, src )
      else
        # puts "debug go remote #{ ip }"
        new_a_remote( src )
      end
    end

    ##
    # new the tcp
    #
    def new_the_tcp
      tcp = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcp.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      tcpd_port = @proxyd_port + 10.times.to_a.sample
      tcpd_addr = Socket.sockaddr_in( tcpd_port, @proxyd_host )

      begin
        tcp.connect_nonblock( tcpd_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect tcpd #{ e.class }"
        tcp.close
        return
      end

      tcp_info = {
        rbuff: '',            # 暂存不满一块的流量
        wbuff: '',            # 写前
        created_at: Time.new, # 创建时间
        last_recv_at: nil     # 上一次收到控制流量时间
      }

      @tcp_infos[ tcp ] = tcp_info
      add_read( tcp, :tcp )
      @tcp = tcp

      hello = @custom.hello
      data = "#{ [ HELLO ].pack( 'C' ) }#{ hello }"
      puts "#{ Time.new } hello i'm #{ hello.inspect } #{ @proxyd_host } #{ tcpd_port }"
      puts "srcs #{ @src_infos.size } dsts #{ @dst_infos.size } tuns #{ @tun_infos.size } dnses #{ @dns_infos.size }"
      add_tcp_wbuff( pack_a_chunk( data ) )
    end

    ##
    # pack a chunk
    #
    def pack_a_chunk( data )
      data = @custom.encode2( data )
      "#{ [ data.bytesize ].pack( 'n' ) }#{ data }"
    end

    ##
    # resolve domain
    #
    def resolve_domain( domain, src )
      return if src.nil? || src.closed?

      if @remotes.any?{ | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) } then
        # puts "debug hit remotes #{ domain }"
        new_a_remote( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ipaddr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug hit resolv cache #{ domain } #{ ipaddr.to_s }"
          new_a_tunnel( ipaddr, src )
          return
        end

        # puts "debug expire resolv cache #{ domain }"
        @resolv_caches.delete( domain )
      end

      src_info = @src_infos[ src ]

      if domain == 'localhost' then
        ip = src_info[ :addrinfo ].ip_address
        # puts "debug redirect #{ domain } #{ ip }"
        ipaddr = IPAddr.new( ip )
        new_a_tunnel( ipaddr, src )
        return
      end

      begin
        ipaddr = IPAddr.new( domain )

        if ipaddr.ipv4? || ipaddr.ipv6? then
          new_a_tunnel( ipaddr, src )
          return
        end
      rescue Exception => e
      end

      begin
        packet = Net::DNS::Packet.new( domain )
      rescue Exception => e
        puts "#{ Time.new } new packet #{ e.class } #{ domain.inspect }"
        close_src( src )
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain }"
        dns.sendmsg_nonblock( packet.data, 0, @nameserver_addr )
      rescue Exception => e
        puts "#{ Time.new } dns sendmsg #{ e.class }"
        dns.close
        close_src( src )
        return
      end

      dns_id = rand( ( 2 ** 64 ) - 2 ) + 1

      dns_info = {
        dns_id: dns_id,
        domain: domain,
        src: src
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )
      src_info[ :proxy_type ] = :checking

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-dns-closed',
          dns_id: dns_id
        }

        send_msg_to_infod( msg )
      end
    end

    ##
    # send msg to client
    #
    def send_msg_to_client( msg, addrinfo )
      begin
        @infod.sendmsg_nonblock( JSON.generate( msg ), 0, addrinfo )
      rescue Exception => e
        puts "#{ Time.new } send msg to client #{ e.class } #{ addrinfo.ip_unpack.inspect }"
      end
    end

    ##
    # send msg to infod
    #
    def send_msg_to_infod( msg )
      begin
        @info.sendmsg( JSON.generate( msg ), 0, @infod_addr )
      rescue Exception => e
        puts "#{ Time.new } send msg to infod #{ e.class }"
      end
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      # puts "debug set dst closing write"
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set src closing write
    #
    def set_src_closing_write( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :closing_write ]
      src_info[ :closing_write ] = true
      add_write( src )
    end

    ##
    # set tun closing write
    #
    def set_tun_closing_write( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing_write ]
      tun_info[ :closing_write ] = true
      add_write( tun )
    end

    ##
    # set tun info pong
    #
    def set_tun_info_pong( tun, src )
      tun_info = @tun_infos[ tun ]
      tun_info[ :pong ] = true
      src_info = @src_infos[ src ]

      unless src_info[ :pong ] then
        if src_info[ :proxy_proto ] == :http then
          if src_info[ :is_connect ] then
            # puts "debug add src wbuff http ok"
            add_src_wbuff( src, HTTP_OK )
          end
        elsif src_info[ :proxy_proto ] == :socks5 then
          add_socks5_conn_reply( src )
        end

        src_info[ :pong ] = true
      end

      unless src_info[ :rbuff ].empty? then
        data = @custom.encode( src_info[ :rbuff ] )
        add_tun_wbuff( tun, data )
      end
    end

    ##
    # read redir
    #
    def read_redir( redir )
      begin
        src, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "accept #{ e.class }"
        return
      end

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug accept a src #{ src_id } #{ addrinfo.ip_unpack.inspect }"

      @src_infos[ src ] = {
        src_id: src_id,          # src id
        addrinfo: addrinfo,      # addrinfo
        proxy_proto: :uncheck,   # :uncheck / :http / :socks5
        proxy_type: :uncheck,    # :uncheck / :checking / :direct / :remote / :negotiation
        destination_domain: nil, # 目的地域名
        destination_port: nil,   # 目的地端口
        is_connect: true,        # 代理协议是http的场合，是否是CONNECT
        rbuff: '',               # 读到的流量
        dst: nil,                # :direct的场合，对应的dst
        dst_id: nil,             # :remote的场合，远端dst id
        tun: nil,                # :remote的场合，对应的tun
        pong: false,             # :remote的场合，连接已确认
        wbuff: '',               # 从dst/tun读到的流量
        closing_write: false,    # 准备关闭写
        paused: false            # 是否暂停
      }

      add_read( src, :src )
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      return if data.empty?

      msg = JSON.parse( data, symbolize_names: true )
      message_type = msg[ :message_type ]

      case message_type
      when 'check-src-paired' then
        src_id = msg[ :src_id ]
        src, src_info = @src_infos.find{ | _, _src_info | ( _src_info[ :src_id ] == src_id ) && _src_info[ :dst_id ].nil? }

        if src then
          puts "#{ Time.new } src pair timeout #{ src_id } #{ src_info[ :destination_domain ] } #{ src_info[ :destination_port ] }"
          close_src( src )

          if @tcp then
            tcp_info = @tcp_infos[ @tcp ]

            if tcp_info && ( Time.new - ( tcp_info[ :last_recv_at ] || tcp_info[ :created_at ] ) >= EXPIRE_TCP ) then
              puts "#{ Time.new } tcp expired"
              close_tcp( @tcp )
            end
          else
            new_the_tcp
          end
        end
      when 'check-dst-connected' then
        dst_id = msg[ :dst_id ]
        dst, dst_info = @dst_infos.find{ | _, _dst_info | ( _dst_info[ :dst_id ] == dst_id ) && !_dst_info[ :connected ] }

        if dst then
          puts "#{ Time.new } dst connect timeout #{ dst_info[ :dst_id ] } #{ dst_info[ :domain ].inspect }"
          close_dst( dst )
        end
      when 'check-tun-pong' then
        tun_id = msg[ :tun_id ]
        tun, tun_info = @tun_infos.find{ | _, _tun_info | ( _tun_info[ :tun_id ] == tun_id ) && !_tun_info[ :pong ] }

        if tun then
          puts "#{ Time.new } tun ping timeout #{ tun_info[ :tun_id ] } #{ tun_info[ :domain ].inspect }"
          close_tun( tun )
        end
      when 'check-dns-closed' then
        dns_id = msg[ :dns_id ]
        dns, dns_info = @dns_infos.find{ | _, _dns_info | ( _dns_info[ :dns_id ] == dns_id ) }

        if dns then
          puts "#{ Time.new } dns expired #{ dns_info[ :dns_id ] } #{ dns_info[ :domain ].inspect }"
          close_dns( dns )
        end
      when 'check-expire' then
        now = Time.new

        @dst_infos.select{ | _, _dst_info | now - ( _dst_info[ :last_add_wbuff_at ] || _dst_info[ :created_at ] ) >= EXPIRE_AFTER }.each do | dst, dst_info |
          puts "#{ Time.new } expire dst #{ dst_info[ :dst_id ] } #{ dst_info[ :domain ].inspect }"
          close_dst( dst )
        end

        @tun_infos.select{ | _, _tun_info | now - ( _tun_info[ :last_add_wbuff_at ] || _tun_info[ :created_at ] ) >= EXPIRE_AFTER }.each do | tun, tun_info |
          puts "#{ Time.new } expire tun #{ tun_info[ :tun_id ] } #{ tun_info[ :domain ].inspect }"
          close_tun( tun )
        end
      when 'memory-info' then
        msg2 = {
          sizes: {
            src_infos: @src_infos.size,
            dst_infos: @dst_infos.size,
            tun_infos: @tun_infos.size,
            dns_infos: @dns_infos.size,
            resolv_caches: @resolv_caches.size
          }
        }

        send_msg_to_client( msg2, addrinfo )
      end
    end

    ##
    # read dns
    #
    def read_dns( dns )
      if dns.closed? then
        puts "#{ Time.new } read dns but dns closed?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "#{ Time.new } dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      return if data.empty?

      # puts "debug recv dns #{ data.inspect }"
      begin
        packet = Net::DNS::Packet::parse( data )
      rescue Exception => e
        puts "#{ Time.new } parse packet #{ e.class }"
        close_dns( dns )
        return
      end

      dns_info = @dns_infos[ dns ]
      src = dns_info[ :src ]
      domain = dns_info[ :domain ]
      ans = packet.answer.find{ | ans | ans.class == Net::DNS::RR::A }

      if ans then
        ipaddr = IPAddr.new( ans.value )
        @resolv_caches[ domain ] = [ ipaddr, Time.new ]
        new_a_tunnel( ipaddr, src )
      else
        puts "#{ Time.new } dns query no answer #{ domain.inspect }"
        close_src( src )
      end

      close_dns( dns )
    end

    ##
    # read tcp
    #
    def read_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } read tcp but tcp closed?"
        return
      end

      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = "#{ tcp_info[ :rbuff ] }#{ data }"

      loop do
        if data.bytesize <= 2 then
          tcp_info[ :rbuff ] = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "#{ Time.new } read tcp zero traffic len?"
          close_tcp( tcp )
          return
        end

        chunk = data[ 2, len ]

        if chunk.bytesize < len then
          tcp_info[ :rbuff ] = data
          break
        end

        data2 = @custom.decode2( chunk )
        deal_ctlmsg( data2, tcp )
        data = data[ ( 2 + len )..-1 ]
      end
    end

    ##
    # deal ctlmsg
    #
    def deal_ctlmsg( data, tcp )
      return if data.nil? || data.empty? || tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :last_recv_at ] = Time.new
      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when TUND_PORTS then
        return if data.bytesize != 21
        tund_ports = data[ 1, 20 ].unpack( 'n*' )
        puts "#{ Time.new } got tund ports #{ tund_ports.inspect }"
        @tund_addrs = tund_ports.map{ | tund_port | Socket.sockaddr_in( tund_port, @proxyd_host ) }
      when PAIRED then
        return if data.bytesize != 17
        src_id, dst_id = data[ 1, 16 ].unpack( 'Q>Q>' )
        return if src_id.nil? || dst_id.nil?
        # puts "debug got paired #{ src_id } #{ dst_id }"
        new_a_tun( src_id, dst_id )
      end
    end

    ##
    # read src
    #
    def read_src( src )
      if src.closed? then
        puts "#{ Time.new } read src but src closed?"
        return
      end

      src_info = @src_infos[ src ]

      begin
        data = src.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read src #{ e.class }"
        close_read_src( src )
        dst = src_info[ :dst ]

        if dst then
          set_dst_closing_write( dst )
        else
          set_tun_closing_write( src_info[ :tun ] )
        end

        return
      end

      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0, 7 ] == 'CONNECT' then
          # puts "debug CONNECT"
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port then
            puts "#{ Time.new } CONNECT miss domain"
            close_src( src )
            return
          end
        elsif data[ 0 ].unpack( 'C' ).first == 5 then
          # puts "debug socks5 #{ data.inspect }"

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
            puts "#{ Time.new } miss method 00"
            close_src( src )
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
          # puts "debug not CONNECT #{ data.inspect }"
          host_line = data.split( "\r\n" ).find{ | _line | _line[ 0, 6 ] == 'Host: ' }

          unless host_line then
            # puts "debug not found host line"
            close_src( src )
            return
          end

          lines = data.split( "\r\n" )

          unless lines.empty? then
            method, url, proto = lines.first.split( ' ' )

            if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://' then
              domain_port = url.split( '/' )[ 2 ]
              # puts "debug domain port #{ domain_port }"
            end
          end

          unless domain_port then
            # puts "debug not HTTP"
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
              puts "#{ Time.new } Host line miss domain"
              close_src( src )
              return
            end
          end

          src_info[ :is_connect ] = false
          src_info[ :rbuff ] << data
        end

        colon_idx = domain_port.rindex( ':' )
        close_idx = domain_port.rindex( ']' )

        if colon_idx && ( close_idx.nil? || ( colon_idx > close_idx ) ) then
          domain = domain_port[ 0...colon_idx ]
          port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
        else
          domain = domain_port
          port = 80
        end

        domain = domain.gsub( /\[|\]/, '' )
        src_info[ :proxy_proto ] = :http
        src_info[ :destination_domain ] = domain
        src_info[ :destination_port ] = port

        resolve_domain( domain, src )
      when :checking then
        # puts "debug add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :negotiation then
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        # puts "debug negotiation #{ data.inspect }"
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1 then
          # puts "debug socks5 CONNECT"

          if atyp == 1 then
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )
            destination_addr = Socket.sockaddr_in( destination_port, destination_host )

            begin
              destination_addrinfo = Addrinfo.new( destination_addr )
            rescue Exception => e
              puts "#{ Time.new } new addrinfo #{ e.class }"
              close_src( src )
              return
            end

            destination_ip = destination_addrinfo.ip_address
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            # puts "debug IP V4 address #{ destination_ip } #{ destination_port }"
            ipaddr = IPAddr.new( destination_ip )
            new_a_tunnel( ipaddr, src )
          elsif atyp == 3 then
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize then
              domain = data[ 5, domain_len ]
              port = data[ ( 5 + domain_len ), 2 ].unpack( 'n' ).first
              src_info[ :destination_domain ] = domain
              src_info[ :destination_port ] = port
              # puts "debug DOMAINNAME #{ domain } #{ port }"
              resolve_domain( domain, src )
            end
          else
            puts "#{ Time.new } socks5 atyp #{ atyp } not implement"
            close_src( src )
          end
        else
          puts "#{ Time.new } socks5 cmd #{ cmd } not implement"
          close_src( src )
        end
      when :remote then
        tun = src_info[ :tun ]

        if tun then
          add_tun_wbuff( tun, @custom.encode( data ) )
        else
          # puts "debug add src rbuff #{ data.bytesize }"
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
        puts "#{ Time.new } read dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_src_closing_write( src )
        return
      end

      add_src_wbuff( src, data )
    end

    ##
    # read tun
    #
    def read_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } read tun but tun closed?"
        return
      end

      tun_info = @tun_infos[ tun ]
      src = tun_info[ :src ]

      if src.closed? then
        close_tun( tun )
        return
      end

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_read_tun( tun )
        set_src_closing_write( src )
        return
      end

      unless tun_info[ :pong ] then
        if data.bytesize < 8 then
          puts "#{ Time.new } pong length less than 8?"
          close_tun( tun )
          return
        end

        src_info = @src_infos[ src ]

        if data[ 0, 8 ].unpack( 'Q>' ).first != src_info[ :src_id ] then
          puts "#{ Time.new } invalid pong?"
          close_tun( tun )
          return
        end

        # puts "debug got pong #{ data.bytesize }"
        set_tun_info_pong( tun, src )
        data = data[ 8..-1 ]

        if data.empty? then
          return
        end
      end

      data = @custom.decode( data )
      add_src_wbuff( src, data )
    end

    ##
    # write tcp
    #
    def write_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } write tcp but tcp closed?"
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = tcp_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        @writes.delete( tcp )
        return
      end

      # 写入
      begin
        written = tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
    end

    ##
    # write src
    #
    def write_src( src )
      if src.closed? then
        puts "#{ Time.new } write src but src closed?"
        return
      end

      src_info = @src_infos[ src ]
      dst = src_info[ :dst ]
      tun = src_info[ :tun ]
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
      rescue Exception => e
        # puts "debug write src #{ e.class }"
        close_write_src( src )

        if dst then
          close_read_dst( dst )
        elsif tun then
          close_read_tun( tun )
        end

        return
      end

      data = data[ written..-1 ]
      src_info[ :wbuff ] = data

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :paused ] && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume dst #{ dst_info[ :domain ].inspect }"
          add_read( dst )
          dst_info[ :paused ] = false
        end
      elsif tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun #{ tun_info[ :domain ].inspect }"
          add_read( tun )
          tun_info[ :paused ] = false
        end
      end
    end

    ##
    # write dst
    #
    def write_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } write dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
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
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_write_dst( dst )
        close_read_src( src )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data

      if src && !src.closed? then
        src_info = @src_infos[ src ]

        if src_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume direct src #{ src_info[ :destination_domain ].inspect }"
          add_read( src )
          src_info[ :paused ] = false
        end
      end
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write tun but tun closed?"
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
      rescue Exception => e
        # puts "debug write tun #{ e.class }"
        close_write_tun( tun )
        close_read_src( src )
        return
      end

      # puts "debug write tun #{ written }"
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data

      if src && !src.closed? then
        src_info = @src_infos[ src ]

        if src_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume remote src #{ src_info[ :destination_domain ].inspect }"
          add_read( src )
          src_info[ :paused ] = false
        end
      end
    end

  end
end
