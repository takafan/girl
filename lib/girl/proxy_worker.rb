module Girl
  class ProxyWorker
    include Custom
    include Dns

    def initialize( redir_port, memd_port, proxyd_host, proxyd_port, girl_port, tspd_port, nameservers, im, directs, remotes, is_client_fastopen, is_server_fastopen )
      @proxyd_host = proxyd_host
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @girl_addr = Socket.sockaddr_in( girl_port, proxyd_host )
      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @im = im
      @directs = directs
      @remotes = remotes
      @is_client_fastopen = is_client_fastopen
      @is_server_fastopen = is_server_fastopen
      @local_ips = Socket.ip_address_list.select{ | info | info.ipv4? }.map{ | info | info.ip_address }

      @update_roles = [ :dns, :dst, :mem, :src, :tun, :rsv, :tsp ] # 参与淘汰的角色
      @updates_limit = 1007  # 淘汰池上限，1015(mac) - [ girlc, info, infod, memd, redir, rsvd, tcp, tspd ]
      @reads = []            # 读池
      @writes = []           # 写池
      @updates = {}          # sock => updated_at
      @eliminate_count = 0   # 淘汰次数
      @roles = {}            # sock =>  :dns / :dst / :infod / :mem / :memd / :redir / :rsv / :rsvd / :src / :tcp / :tspd /:tun
      @resolv_caches = {}    # domain => [ ip, created_at ]
      @is_direct_caches = {} # ip => true / false
      @tcp_infos = {}        # tcp => { :part :wbuff :created_at :last_recv_at :is_syn }
      @mem_infos = {}        # mem => { :wbuff }
      @src_infos = {}        # src => { :src_id :addrinfo :proxy_proto :proxy_type :destination_domain :destination_port :is_connect :rbuffs :dst :dst_id :tcp :tun :wbuff :closing :paused :left }
      @dst_infos = {}        # dst => { :dst_id :src :domain :connected :wbuff :closing :paused }
      @tun_infos = {}        # tun => { :tun_id :src :domain :pong :part :wbuff :closing :paused :is_syn }
      @dns_infos = {}        # dns => { :dns_id :domain :src }
      @rsv_infos = {}        # rsv => { :rsv_id :addrinfo :domain }
      @near_infos = {}       # near_id => { :addrinfo :id :domain :part }
      @response_caches = {}  # domain => [ response, created_at, ip, is_remote ]
      @response6_caches = {} # domain => [ response, created_at, ip, is_remote ]

      new_a_redir( redir_port )
      new_a_infod( redir_port )
      new_a_memd( memd_port )
      new_a_rsvd( tspd_port )
      new_a_tspd( tspd_port )
      new_a_girlc
    end

    def looping
      puts "#{ Time.new } looping"
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dns then
            read_dns( sock )
          when :dst then
            read_dst( sock )
          when :infod then
            read_infod( sock )
          when :mem then
            read_mem( sock )
          when :memd then
            read_memd( sock )
          when :redir then
            read_redir( sock )
          when :rsv then
            read_rsv( sock )
          when :rsvd then
            read_rsvd( sock )
          when :src then
            read_src( sock )
          when :tcp then
            read_tcp( sock )
          when :tspd then
            read_tspd( sock )
          when :tun then
            read_tun( sock )
          else
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :dst then
            write_dst( sock )
          when :mem then
            write_mem( sock )
          when :src then
            write_src( sock )
          when :tcp then
            write_tcp( sock )
          when :tun then
            write_tun( sock )
          else
            close_sock( sock )
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      exit
    end

    private

    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed? || data.empty?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )
      return if dst.closed?

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = dst_info[ :src ]

        if src && !src.closed? then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause direct src #{ src_info[ :destination_domain ] }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    def add_mem_wbuff( mem, data )
      return if mem.nil? || mem.closed? || data.empty?
      mem_info = @mem_infos[ mem ]
      mem_info[ :wbuff ] << data
      add_write( mem )
    end

    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      else
        role = @roles[ sock ]
      end

      if @update_roles.include?( role ) then
        set_update( sock )
      end
    end

    def add_socks5_conn_reply( src )
      # +----+-----+-------+------+----------+----------+
      # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      # +----+-----+-------+------+----------+----------+
      # | 1  |  1  | X'00' |  1   | Variable |    2     |
      # +----+-----+-------+------+----------+----------+
      redir_ip, redir_port = @redir_local_address.ip_unpack
      data = [ [ 5, 0, 0, 1 ].pack( 'C4' ), IPAddr.new( redir_ip ).hton, [ redir_port ].pack( 'n' ) ].join
      add_src_wbuff( src, data )
    end

    def add_src_rbuff( src, data )
      return if src.nil? || src.closed? || data.empty?
      src_info = @src_infos[ src ]
      src_info[ :rbuffs ] << data

      if src_info[ :rbuffs ].join.bytesize >= WBUFF_LIMIT then
        puts "#{ Time.new } src rbuff full"
        close_src( src )
      end
    end

    def add_src_wbuff( src, data )
      return if src.nil? || src.closed? || data.empty?
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      add_write( src )
      return if src.closed?

      if src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :domain ] }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        else
          tun = src_info[ :tun ]

          if tun then
            tun_info = @tun_infos[ tun ]

            if tun_info then
              puts "#{ Time.new } pause tun #{ tun_info[ :domain ] }"
              @reads.delete( tun )
              tun_info[ :paused ] = true
            end
          end
        end
      end
    end

    def add_tcp_wbuff( data )
      return if data.empty?

      if @tcp.nil? || @tcp.closed? then
        tcp_info = new_a_tcp
        puts "#{ Time.new } #{ @im }"
        data2 = [ Girl::Custom::HELLO, @im ].join( Girl::Custom::SEP )
        tcp_info[ :wbuff ] << encode_a_msg( data2 )
      else
        tcp_info = @tcp_infos[ @tcp ]
      end

      tcp_info[ :wbuff ] << data
      add_write( @tcp )
    end

    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed? || data.empty?
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      add_write( tun )
      return if tun.closed?

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = tun_info[ :src ]

        if src && !src.closed? then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause remote src #{ src_info[ :destination_domain ] }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
      role = @roles[ sock ]

      if @update_roles.include?( role ) then
        set_update( sock )
      end
    end

    def close_dns( dns )
      return nil if dns.nil? || dns.closed?
      close_sock( dns )
      dns_info = @dns_infos.delete( dns )
      dns_info
    end

    def close_dst( dst )
      return nil if dst.nil? || dst.closed?
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      set_src_closing( dst_info[ :src ] ) if dst_info
      dst_info
    end

    def close_mem( mem )
      return nil if mem.nil? || mem.closed?
      close_sock( mem )
      @mem_infos.delete( mem )
    end

    def close_rsv( rsv )
      return nil if rsv.nil? || rsv.closed?
      close_sock( rsv )
      rsv_info = @rsv_infos.delete( rsv )
      rsv_info
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @updates.delete( sock )
      @roles.delete( sock )
    end

    def close_src( src )
      return nil if src.nil? || src.closed?
      close_sock( src )
      src_info = @src_infos.delete( src )

      if src_info then
        if src_info[ :dst ] then
          set_dst_closing( src_info[ :dst ] )
        else
          set_tun_closing( src_info[ :tun ] )
        end
      end

      src_info
    end

    def close_tcp( tcp )
      return if tcp.nil? || tcp.closed?
      close_sock( tcp )
      @tcp_infos.delete( tcp )
    end

    def close_tun( tun )
      return nil if tun.nil? || tun.closed?
      close_sock( tun )
      tun_info = @tun_infos.delete( tun )
      set_src_closing( tun_info[ :src ] ) if tun_info
      tun_info
    end

    def deal_ctlmsg( data )
      return if data.nil? || data.empty?
      ctl_chr = data[ 0 ]

      case ctl_chr
      when Girl::Custom::PAIRED then
        _, src_id, dst_id = data.split( Girl::Custom::SEP, 3 )
        return if src_id.nil? || dst_id.nil?
        src_id = src_id.to_i
        dst_id = dst_id.to_i
        return if src_id <= 0 || dst_id <= 0
        new_a_tun( src_id, dst_id )
      when Girl::Custom::INCOMPLETE then
        _, near_id, data2 = data.split( Girl::Custom::SEP, 3 )
        return if near_id.nil? || data2.nil?
        near_id = near_id.to_i
        return if near_id <= 0
        near_info = @near_infos[ near_id ]
        near_info[ :part ] << data2 if near_info
      when Girl::Custom::RESPONSE then
        _, near_id, data2 = data.split( Girl::Custom::SEP, 3 )
        return if near_id.nil? || data2.nil?
        near_id = near_id.to_i
        return if near_id <= 0
        near_info = @near_infos.delete( near_id )

        if near_info then
          addrinfo = near_info[ :addrinfo ]
          domain = near_info[ :domain ]
          type = near_info[ :type ]
          data2 = near_info[ :part ] + data2
          data2[ 0, 2 ] = near_info[ :id ]
          send_data( @rsvd, data2, addrinfo )

          begin
            ip = seek_ip( data2 )
          rescue Exception => e
            puts "#{ Time.new } response seek ip  #{ e.class } #{ e.message }"
          end

          if ip then
            if type == 1 then
              @response_caches[ domain ] = [ data2, Time.new, ip, true ]
            else
              @response6_caches[ domain ] = [ data2, Time.new, ip, true ]
            end
          end
        end
      end
    end

    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          msg = {
            message_type: 'check-expire'
          }

          send_data( @info, JSON.generate( msg ), @infod_addr )
        end
      end
    end

    def make_tunnel( ip, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]

      if @local_ips.include?( ip ) && [ @redir_port, @tspd_port ].include?( port ) then
        puts "#{ Time.new } ignore #{ ip }:#{ port }"
        close_src( src )
        return
      end

      if [ domain, ip ].include?( @proxyd_host )  then
        # 访问远端，直连
        puts "#{ Time.new } direct #{ ip } #{ port }"
        new_a_dst( ip, src )
        return
      end

      if @is_direct_caches.include?( ip ) then
        is_direct = @is_direct_caches[ ip ]
      else
        begin
          is_direct = @directs.any?{ | direct | direct.include?( ip ) }
        rescue IPAddr::InvalidAddressError => e
          puts "#{ Time.new } make tunnel #{ e.class }"
          close_src( src )
          return
        end

        @is_direct_caches[ ip ] = is_direct
      end

      if is_direct then
        new_a_dst( ip, src )
      else
        set_remote( src )
      end
    end

    def new_a_dst( ip, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]

      begin
        destination_addr = Socket.sockaddr_in( port, ip )
        dst = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ e.class } #{ domain } #{ ip }:#{ port }"
        close_src( src )
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } dst connect destination #{ e.class } #{ domain } #{ ip }:#{ port }"
        dst.close
        close_src( src )
        return
      end

      dst_id = rand( ( 2 ** 64 ) - 2 ) + 1

      dst_info = {
        dst_id: dst_id,
        src: src,
        domain: domain,
        ip: ip,
        connected: false,
        wbuff: '',
        closing: false,
        paused: false
      }

      @dst_infos[ dst ] = dst_info
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          add_src_wbuff( src, HTTP_OK )
        elsif src_info[ :rbuffs ].any? then
          dst_info[ :wbuff ] << src_info[ :rbuffs ].join
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_socks5_conn_reply( src )
      end

      add_read( dst, :dst )
      add_write( dst )
      return if dst.closed?

      Thread.new do
        sleep EXPIRE_CONNECTING

        msg = {
          message_type: 'check-dst-connected',
          dst_id: dst_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def new_a_girlc
      girlc = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @girlc = girlc
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      infod.bind( infod_addr )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_memd( memd_port )
      memd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      memd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 ) if @is_server_fastopen
      memd.bind( Socket.sockaddr_in( memd_port, '127.0.0.1' ) )
      memd.listen( 5 )
      puts "#{ Time.new } memd listen on #{ memd_port }"
      add_read( memd, :memd )
    end

    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( BACKLOG )
      puts "#{ Time.new } redir listen on #{ redir_port }"
      add_read( redir, :redir )
      @redir_port = redir_port
      @redir_local_address = redir.local_address
    end

    def new_a_tspd( tspd_port )
      tspd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tspd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tspd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      tspd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      tspd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      tspd.bind( Socket.sockaddr_in( tspd_port, '0.0.0.0' ) )
      tspd.listen( BACKLOG )
      puts "#{ Time.new } tspd listen on #{ tspd_port }"
      add_read( tspd, :tspd )
      @tspd_port = tspd_port
    end

    def new_a_rsv( data, addrinfo, domain, type )
      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        @nameserver_addrs.each{ | addr | rsv.sendmsg( data, 0, addr ) }
      rescue Exception => e
        puts "#{ Time.new } rsv send data #{ e.class }"
        rsv.close
        return
      end

      rsv_id = rand( ( 2 ** 64 ) - 2 ) + 1
      rsv_info = {
        rsv_id: rsv_id,
        addrinfo: addrinfo,
        domain: domain,
        type: type
      }

      @rsv_infos[ rsv ] = rsv_info
      add_read( rsv, :rsv )
      return if rsv.closed?

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-rsv-closed',
          rsv_id: rsv_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def new_a_rsvd( rsvd_port )
      rsvd_addr = Socket.sockaddr_in( rsvd_port, '0.0.0.0' )
      rsvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      rsvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      rsvd.bind( rsvd_addr )
      puts "#{ Time.new } rsvd bind on #{ rsvd_port }"
      add_read( rsvd, :rsvd )
      @rsvd = rsvd
    end

    def new_a_tcp
      send_data( @girlc, encode_im( @im ), @girl_addr )
      tcp = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcp.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      if @is_client_fastopen then
        tcp.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 )
      else
        begin
          tcp.connect_nonblock( @proxyd_addr )
        rescue IO::WaitWritable
        rescue Exception => e
          puts "#{ Time.new } connect tcpd #{ e.class }"
          tcp.close
          return
        end
      end

      tcp_info = {
        part: '',
        wbuff: '',
        created_at: Time.new,
        last_recv_at: nil,
        is_syn: @is_client_fastopen
      }

      add_read( tcp, :tcp )
      @tcp = tcp
      @tcp_infos[ tcp ] = tcp_info
      tcp_info
    end

    def new_a_tun( src_id, dst_id )
      src, src_info = @src_infos.find{ | _, info | ( info[ :src_id ] == src_id ) && info[ :dst_id ].nil? }
      return unless src
      src_info[ :dst_id ] = dst_id
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      if @is_client_fastopen then
        tun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 )
      else
        begin
          tun.connect_nonblock( @girl_addr )
        rescue IO::WaitWritable
        rescue Exception => e
          puts "#{ Time.new } connect tund #{ e.class }"
          tun.close
          close_src( src )
          return
        end
      end

      domain = src_info[ :destination_domain ]
      tun_id = rand( ( 2 ** 64 ) - 2 ) + 1

      tun_info = {
        tun_id: tun_id,
        src: src,
        domain: domain,
        pong: false,
        part: '',
        wbuff: "#{ dst_id }#{ Girl::Custom::SEP }",
        closing: false,
        paused: false,
        is_syn: @is_client_fastopen
      }

      @tun_infos[ tun ] = tun_info
      src_info[ :tun ] = tun
      src_info[ :left ] = Girl::Custom::WAVE

      src_info[ :rbuffs ].each do | data |
        if src_info[ :left ] > 0 then
          data = encode( data )
          src_info[ :left ] -= 1
          data << Girl::Custom::TERM if src_info[ :left ] == 0
        end

        tun_info[ :wbuff ] << data
      end

      add_read( tun, :tun )
      add_write( tun )
      return if tun.closed?

      Thread.new do
        sleep PING_TIMEOUT

        msg = {
          message_type: 'check-tun-pong',
          tun_id: tun_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def read_dns( dns )
      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "#{ Time.new } dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      return if data.empty?

      begin
        ip = seek_ip( data )
      rescue Exception => e
        puts "#{ Time.new } dns seek ip #{ e.class } #{ e.message }"
        close_dns( dns )
        return
      end

      dns_info = @dns_infos[ dns ]
      domain = dns_info[ :domain ]

      if ip then
        src = dns_info[ :src ]
        make_tunnel( ip, src )
        @resolv_caches[ domain ] = [ ip, Time.new ]
      else
        puts "#{ Time.new } no ip in answer #{ domain }"
        close_src( src )
      end

      close_dns( dns )
    end

    def read_dst( dst )
      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_dst( dst )
        return
      end

      set_update( dst )
      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]
      add_src_wbuff( src, data )
    end

    def read_infod( infod )
      begin
        data, addrinfo, rflags, *controls = infod.recvmsg
      rescue Exception => e
        puts "#{ Time.new } infod recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      begin
        msg = JSON.parse( data, symbolize_names: true )
      rescue JSON::ParserError, EncodingError => e
        puts "#{ Time.new } read infod #{ e.class }"
        return
      end

      message_type = msg[ :message_type ]

      case message_type
      when 'check-src-paired' then
        src_id = msg[ :src_id ]
        src, src_info = @src_infos.find{ | _, _info | ( _info[ :src_id ] == src_id ) }

        if src then
          if [ :uncheck, :checking, :negotiation ].include?( src_info[ :proxy_type ] ) then
            puts "#{ Time.new } src check timeout #{ src_id } #{ src_info[ :proxy_type ] } #{ src_info[ :destination_domain ] } #{ src_info[ :destination_port ] }"
            close_src( src )
          elsif ( src_info[ :proxy_type ] == :remote ) && src_info[ :dst_id ].nil? then
            puts "#{ Time.new } src pair timeout #{ src_id } #{ src_info[ :destination_domain ] } #{ src_info[ :destination_port ] }"
            close_src( src )

            if @tcp then
              tcp_info = @tcp_infos[ @tcp ]

              if tcp_info && ( Time.new - ( tcp_info[ :last_recv_at ] || tcp_info[ :created_at ] ) >= EXPIRE_TCP ) then
                puts "#{ Time.new } tcp expired"
                close_tcp( @tcp )
              end
            end
          end
        end
      when 'check-dst-connected' then
        dst_id = msg[ :dst_id ]
        dst, dst_info = @dst_infos.find{ | _, _info | ( _info[ :dst_id ] == dst_id ) && !_info[ :connected ] }

        if dst then
          puts "#{ Time.new } dst connect timeout #{ dst_info[ :dst_id ] } #{ dst_info[ :domain ] }"
          close_dst( dst )
        end
      when 'check-tun-pong' then
        tun_id = msg[ :tun_id ]
        tun, tun_info = @tun_infos.find{ | _, _info | ( _info[ :tun_id ] == tun_id ) && !_info[ :pong ] }

        if tun then
          puts "#{ Time.new } tun ping timeout #{ tun_info[ :tun_id ] } #{ tun_info[ :domain ] }"
          close_tun( tun )
        end
      when 'check-dns-closed' then
        dns_id = msg[ :dns_id ]
        dns, dns_info = @dns_infos.find{ | _, _info | _info[ :dns_id ] == dns_id }

        if dns then
          puts "#{ Time.new } dns expired #{ dns_info[ :dns_id ] } #{ dns_info[ :domain ] }"
          close_dns( dns )
        end
      when 'check-expire' then
        now = Time.new
        socks = @updates.select{ | _, updated_at | now - updated_at >= EXPIRE_AFTER }.keys

        socks.each do | sock |
          case @roles[ sock ]
          when :dns
            dns_info = close_dns( sock )
            puts "#{ Time.new } expire dns #{ dns_info[ :domain ] }" if dns_info
          when :dst
            dst_info = close_dst( sock )
            puts "#{ Time.new } expire dst #{ dst_info[ :domain ] }" if dst_info
          when :mem
            close_mem( sock )
          when :src
            src_info = close_src( sock )
            puts "#{ Time.new } expire src #{ src_info[ :destination_domain ] }" if src_info
          when :tun
            tun_info = close_tun( sock )
            puts "#{ Time.new } expire tun #{ tun_info[ :domain ] }" if tun_info
          when :rsv
            rsv_info = close_rsv( sock )
            puts "#{ Time.new } expire rsv #{ rsv_info[ :domain ] }" if rsv_info
          else
            close_sock( sock )
          end
        end
      when 'check-rsv-closed' then
        rsv_id = msg[ :rsv_id ]
        rsv, rsv_info = @rsv_infos.find{ | _, _info | _info[ :rsv_id ] == rsv_id }

        if rsv then
          puts "#{ Time.new } rsv expired #{ rsv_info[ :rsv_id ] } #{ rsv_info[ :domain ] }"
          close_rsv( rsv )
        end
      when 'expire-near' then
        near_id = msg[ :near_id ]
        near_info = @near_infos.delete( near_id )
        puts "#{ Time.new } expire near #{ near_info[ :addrinfo ].ip_unpack.inspect } #{ near_info[ :domain ] }" if near_info
      end
    end

    def read_mem( mem )
      begin
        mem.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_mem( mem )
        return
      end

      set_update( mem )

      msg = {
        resolv_caches: @resolv_caches.sort,
        response_caches: @response_caches.sort.map{ | a | [ a[ 0 ], a[ 1 ][ 2 ], a[ 1 ][ 3 ] ] },
        response6_caches: @response6_caches.sort.map{ | a | [ a[ 0 ], a[ 1 ][ 2 ], a[ 1 ][ 3 ] ] },
        sizes: {
          directs: @directs.size,
          remotes: @remotes.size,
          reads: @reads.size,
          writes: @writes.size,
          updates: @updates.size,
          mem_infos: @mem_infos.size,
          src_infos: @src_infos.size,
          dst_infos: @dst_infos.size,
          tun_infos: @tun_infos.size,
          dns_infos: @dns_infos.size,
          resolv_caches: @resolv_caches.size,
          rsv_infos: @rsv_infos.size,
          near_infos: @near_infos.size,
          response_caches: @response_caches.size,
          response6_caches: @response6_caches.size
        },
        updates_limit: @updates_limit,
        eliminate_count: @eliminate_count
      }

      add_mem_wbuff( mem, JSON.generate( msg ) )
    end

    def read_memd( memd )
      begin
        mem, addrinfo = memd.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } memd accept #{ e.class }"
        return
      end

      @mem_infos[ mem ] = {
        wbuff: ''
      }

      add_read( mem, :mem )
    end

    def read_redir( redir )
      begin
        src, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "redir accept #{ e.class }"
        return
      end

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1

      @src_infos[ src ] = {
        src_id: src_id,
        addrinfo: addrinfo,
        proxy_proto: :uncheck, # :uncheck / :http / :socks5
        proxy_type: :uncheck,  # :uncheck / :checking / :negotiation / :remote / :direct
        destination_domain: nil,
        destination_port: nil,
        is_connect: true,
        rbuffs: [],
        dst: nil,
        dst_id: nil,
        tun: nil,
        wbuff: '',
        closing: false,
        paused: false,
        left: 0
      }

      add_read( src, :src )
      return if src.closed?

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-src-paired',
          src_id: src_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def read_rsv( rsv )
      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "#{ Time.new } rsv recvmsg #{ e.class }"
        close_rsv( rsv )
        return
      end

      return if data.empty?

      rsv_info = @rsv_infos[ rsv ]
      addrinfo = rsv_info[ :addrinfo ]
      domain = rsv_info[ :domain ]
      type = rsv_info[ :type ]
      send_data( @rsvd, data, addrinfo )

      begin
        ip = seek_ip( data )
      rescue Exception => e
        puts "#{ Time.new } rsv seek ip #{ e.class } #{ e.message }"
        close_rsv( rsv )
        return
      end

      if ip then
        if type == 1 then
          @response_caches[ domain ] = [ data, Time.new, ip, false ]
        else
          @response6_caches[ domain ] = [ data, Time.new, ip, false ]
        end
      end

      close_rsv( rsv )
    end

    def read_rsvd( rsvd )
      begin
        data, addrinfo, rflags, *controls = rsvd.recvmsg
      rescue Exception => e
        puts "#{ Time.new } rsvd recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      begin
        id, domain, type = seek_question_dn( data )
      rescue Exception => e
        puts "#{ Time.new } seek question dn #{ e.class } #{ e.message }"
        return
      end

      return unless [ 1, 12, 28 ].include?( type )

      if type == 12 then
        new_a_rsv( data, addrinfo, domain, type )
        return
      end

      if type == 1 then
        response_cache = @response_caches[ domain ]
      else
        response_cache = @response6_caches[ domain ]
      end

      if response_cache then
        response, created_at = response_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          response[ 0, 2 ] = id
          send_data( @rsvd, response, addrinfo )
          return
        end

        if type == 1 then
          @response_caches.delete( domain )
        else
          @response6_caches.delete( domain )
        end
      end

      if @remotes.any?{ | r | domain.include?( r ) } then
        near_id = rand( ( 2 ** 64 ) - 2 ) + 1

        @near_infos[ near_id ] = {
          addrinfo: addrinfo,
          id: id,
          domain: domain,
          type: type,
          part: ''
        }

        data2 = [ Girl::Custom::QUERY, near_id, type, domain ].join( Girl::Custom::SEP )
        add_tcp_wbuff( encode_a_msg( data2 ) )

        Thread.new do
          sleep EXPIRE_NEW

          msg = {
            message_type: 'expire-near',
            near_id: near_id
          }

          send_data( @info, JSON.generate( msg ), @infod_addr )
        end

        return
      end

      new_a_rsv( data, addrinfo, domain, type )
    end

    def read_src( src )
      begin
        data = src.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_src( src )
        return
      end

      set_update( src )
      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0, 7 ] == 'CONNECT' then
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port then
            puts "#{ Time.new } CONNECT miss domain"
            close_src( src )
            return
          end
        elsif data[ 0 ].unpack( 'C' ).first == 5 then
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
          return if src.closed?
          src_info[ :proxy_proto ] = :socks5
          src_info[ :proxy_type ] = :negotiation
          return
        else
          host_line = data.split( "\r\n" ).find{ | _line | _line[ 0, 6 ] == 'Host: ' }

          unless host_line then
            close_src( src )
            return
          end

          lines = data.split( "\r\n" )

          unless lines.empty? then
            method, url, proto = lines.first.split( ' ' )

            if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://' then
              domain_port = url.split( '/' )[ 2 ]
            end
          end

          unless domain_port then
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
              puts "#{ Time.new } Host line miss domain"
              close_src( src )
              return
            end
          end

          src_info[ :is_connect ] = false
          src_info[ :rbuffs ] << data
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
        src_info[ :rbuffs ] << data
      when :negotiation then
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1 then
          if atyp == 1 then
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )

            begin
              destination_addr = Socket.sockaddr_in( destination_port, destination_host )
              destination_addrinfo = Addrinfo.new( destination_addr )
            rescue Exception => e
              puts "#{ Time.new } new addrinfo #{ e.class }"
              close_src( src )
              return
            end

            destination_ip = destination_addrinfo.ip_address
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            make_tunnel( destination_ip, src )
          elsif atyp == 3 then
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize then
              domain = data[ 5, domain_len ]
              port = data[ ( 5 + domain_len ), 2 ].unpack( 'n' ).first
              src_info[ :destination_domain ] = domain
              src_info[ :destination_port ] = port
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
          if src_info[ :left ] > 0 then
            data = encode( data )
            src_info[ :left ] -= 1
            data << Girl::Custom::TERM if src_info[ :left ] == 0
          end

          add_tun_wbuff( tun, data )
        else
          add_src_rbuff( src, data )
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          add_dst_wbuff( dst, data )
        else
          add_src_rbuff( src, data )
        end
      end
    end

    def read_tcp( tcp )
      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_tcp( tcp )
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :last_recv_at ] = Time.new
      data = "#{ tcp_info[ :part ] }#{ data }"

      msgs, part = decode_to_msgs( data )
      msgs.each{ | msg | deal_ctlmsg( msg ) }
      tcp_info[ :part ] = part
    end

    def read_tspd( tspd )
      begin
        src, addrinfo = tspd.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "tspd accept #{ e.class }"
        return
      end

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = src.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        src.close
        return
      end

      dest_family, dest_port, dest_host = option.unpack( 'nnN' )
      dest_addr = Socket.sockaddr_in( dest_port, dest_host )
      dest_addrinfo = Addrinfo.new( dest_addr )
      dest_ip = dest_addrinfo.ip_address
      src_id = rand( ( 2 ** 64 ) - 2 ) + 1

      @src_infos[ src ] = {
        src_id: src_id,
        addrinfo: addrinfo,
        proxy_proto: :uncheck, # :uncheck / :http / :socks5
        proxy_type: :uncheck,  # :uncheck / :checking / :negotiation / :remote / :direct
        destination_domain: dest_ip,
        destination_port: dest_port,
        is_connect: true,
        rbuffs: [],
        dst: nil,
        dst_id: nil,
        tun: nil,
        wbuff: '',
        closing: false,
        paused: false,
        left: 0
      }

      add_read( src, :src )
      return if src.closed?
      make_tunnel( dest_ip, src )

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-src-paired',
          src_id: src_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def read_tun( tun )
      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_tun( tun )
        return
      end

      set_update( tun )
      tun_info = @tun_infos[ tun ]
      src = tun_info[ :src ]

      return if src.closed?

      unless tun_info[ :pong ] then
        sep_idx = data.index( Girl::Custom::SEP )

        unless sep_idx then
          puts "#{ Time.new } miss pong sep? #{ data.inspect[ 0, 255 ] }"
          close_tun( tun )
          return
        end

        src_id = data[ 0, sep_idx ].to_i
        src_info = @src_infos[ src ]

        if src_id != src_info[ :src_id ] then
          puts "#{ Time.new } invalid pong?"
          close_tun( tun )
          return
        end

        set_pong( tun, src )
        data = data[ ( sep_idx + 1 )..-1 ]

        if data.empty? then
          return
        end
      end

      if tun_info[ :part ] != Girl::Custom::TERM then
        data = "#{ tun_info[ :part ] }#{ data }"
        data, part = decode( data )
        tun_info[ :part ] = part
      end

      add_src_wbuff( src, data )
    end

    def resolve_domain( domain, src )
      return if src.nil? || src.closed?

      unless domain =~ /^[0-9a-zA-Z\-\.]{1,63}$/ then
        # 忽略非法域名
        puts "#{ Time.new } ignore #{ domain }"
        close_src( src )
        return
      end

      if domain == 'localhost' then
        domain = "127.0.0.1"
      end

      if domain =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/ then
        # ipv4
        make_tunnel( domain, src )
        return
      end

      if @remotes.any?{ | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) } then
        set_remote( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          make_tunnel( ip, src )
          return
        end

        @resolv_caches.delete( domain )
      end

      begin
        data = pack_a_query( domain )
      rescue Exception => e
        puts "#{ Time.new } pack a query #{ e.class } #{ e.message } #{ domain }"
        close_src( src )
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        @nameserver_addrs.each{ | addr | dns.sendmsg( data, 0, addr ) }
      rescue Exception => e
        puts "#{ Time.new } dns send data #{ e.class }"
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
      return if dns.closed?

      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :checking

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-dns-closed',
          dns_id: dns_id
        }

        send_data( @info, JSON.generate( msg ), @infod_addr )
      end
    end

    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg( data, 0, target_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class }"
      end
    end

    def set_dst_closing( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info.nil? || dst_info[ :closing ]
      dst_info[ :closing ] = true
      add_write( dst )
    end

    def set_pong( tun, src )
      tun_info = @tun_infos[ tun ]
      tun_info[ :pong ] = true
      src_info = @src_infos[ src ]

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          add_src_wbuff( src, HTTP_OK )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        add_socks5_conn_reply( src )
      end
    end

    def set_remote( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :remote
      src_id = src_info[ :src_id ]
      destination_domain = src_info[ :destination_domain ]
      destination_port = src_info[ :destination_port ]
      domain_port = [ destination_domain, destination_port ].join( ':' )
      data = [ Girl::Custom::A_NEW_SOURCE, src_id, domain_port ].join( Girl::Custom::SEP )
      add_tcp_wbuff( encode_a_msg( data ) )
    end

    def set_src_closing( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info.nil? || src_info[ :closing ]
      src_info[ :closing ] = true
      add_write( src )
    end

    def set_tun_closing( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info.nil? || tun_info[ :closing ]
      tun_info[ :closing ] = true
      add_write( tun )
    end

    def set_update( sock )
      @updates[ sock ] = Time.new

      if @updates_limit - @updates.size <= 20 then
        puts "updates #{ @updates.size }"
      end

      if @updates.size >= @updates_limit then
        puts "#{ Time.new } eliminate updates"

        @updates.keys.each do | _sock |
          case @roles[ _sock ]
          when :dns
            close_dns( _sock )
          when :dst
            close_dst( _sock )
          when :mem
            close_mem( _sock )
          when :src
            close_src( _sock )
          when :tun
            close_tun( _sock )
          when :rsv
            close_rsv( _sock )
          else
            close_sock( _sock )
          end
        end

        @eliminate_count += 1
      end
    end

    def write_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } write closed dst?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
      data = dst_info[ :wbuff ]

      if data.empty? then
        if dst_info[ :closing ] then
          close_dst( dst )
        else
          @writes.delete( dst )
        end

        return
      end

      begin
        written = dst.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_dst( dst )
        return
      end

      set_update( dst )
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      src = dst_info[ :src ]

      if src && !src.closed? then
        src_info = @src_infos[ src ]

        if src_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume direct src #{ src_info[ :destination_domain ] }"
          add_read( src )
          src_info[ :paused ] = false unless src.closed?
        end
      end
    end

    def write_mem( mem )
      if mem.closed? then
        puts "#{ Time.new } write closed mem?"
        return
      end

      mem_info = @mem_infos[ mem ]
      data = mem_info[ :wbuff ]

      if data.empty? then
        @writes.delete( mem )
        close_mem( mem )
        return
      end

      begin
        written = mem.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_mem( mem )
        return
      end

      set_update( mem )
      data = data[ written..-1 ]
      mem_info[ :wbuff ] = data
    end

    def write_src( src )
      if src.closed? then
        puts "#{ Time.new } write closed src?"
        return
      end

      src_info = @src_infos[ src ]
      data = src_info[ :wbuff ]

      if data.empty? then
        if src_info[ :closing ] then
          close_src( src )
        else
          @writes.delete( src )
        end

        return
      end

      begin
        written = src.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_src( src )
        return
      end

      set_update( src )
      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
      dst = src_info[ :dst ]
      tun = src_info[ :tun ]

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :paused ] && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume dst #{ dst_info[ :domain ] }"
          add_read( dst )
          dst_info[ :paused ] = false unless dst.closed?
        end
      elsif tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun #{ tun_info[ :domain ] }"
          add_read( tun )
          tun_info[ :paused ] = false unless tun.closed?
        end
      end
    end

    def write_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } write closed tcp?"
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = tcp_info[ :wbuff ]

      if data.empty? then
        @writes.delete( tcp )
        return
      end

      begin
        if tcp_info[ :is_syn ] then
          written = tcp.sendmsg_nonblock( data, 536870912, @proxyd_addr )
          tcp_info[ :is_syn ] = false
        else
          written = tcp.write_nonblock( data )
        end
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_tcp( tcp )
        return
      end

      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
    end

    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write closed tun?"
        return
      end

      tun_info = @tun_infos[ tun ]
      data = tun_info[ :wbuff ]

      if data.empty? then
        if tun_info[ :closing ] then
          close_tun( tun )
        else
          @writes.delete( tun )
        end

        return
      end

      begin
        if tun_info[ :is_syn ] then
          written = tun.sendmsg_nonblock( data, 536870912, @girl_addr )
          tun_info[ :is_syn ] = false
        else
          written = tun.write_nonblock( data )
        end
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_tun( tun )
        return
      end

      set_update( tun )
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data
      src = tun_info[ :src ]

      if src && !src.closed? then
        src_info = @src_infos[ src ]

        if src_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume remote src #{ src_info[ :destination_domain ] }"
          add_read( src )
          src_info[ :paused ] = false unless src.closed?
        end
      end
    end

  end
end
