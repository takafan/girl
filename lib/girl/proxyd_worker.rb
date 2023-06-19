module Girl
  class ProxydWorker
    include Custom
    include Dns

    def initialize( proxyd_port, girl_port, nameservers, reset_traff_day, ims )
      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @reset_traff_day = reset_traff_day
      @ims = ims

      @updates_limit = 1019                      # 应对 FD_SETSIZE (1024)，参与淘汰的更新池上限，1023 - [ girl, infod, tcpd, tund ] = 1019
      @eliminate_size = @updates_limit - 255     # 淘汰数，保留255个最近的，其余淘汰
      @update_roles = [ :dns, :dst, :tcp, :tun ] # 参与淘汰的角色
      @reads = []                                # 读池
      @writes = []                               # 写池
      
      @updates = {}       # sock => updated_at
      @roles = {}         # sock => :dns / :dst / :girl / :infod / :tcpd / :tcp / :tund / :tun
      @tcp_infos = {}     # tcp => { :part, :wbuff, :im }
      @resolv_caches = {} # domain => [ ip, created_at ]
      @dst_infos = {}     # dst => { :dst_id, :im, :domain, :ip, :rbuff, :tun, :wbuff, :src_id, :connected, :closing, :paused }
      @tun_infos = {}     # tun => { :im, :dst, :domain, :wbuff, :paused }
      @dns_infos = {}     # dns => { :dns_id, :im, :src_id, :domain, :port, :tcp }
      @ips = {}           # im => ip
      @im_infos = {}      # im => { :in, :out }
      
      new_a_tcpd( proxyd_port )
      new_a_infod( proxyd_port )
      new_a_tund( girl_port )
      new_a_girl( girl_port )
    end

    def looping
      puts "#{ Time.new } looping"
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dns then
            read_dns( sock )
          when :dst then
            read_dst( sock )
          when :girl then
            read_girl( sock )
          when :infod then
            read_infod( sock )
          when :tcpd then
            read_tcpd( sock )
          when :tcp then
            read_tcp( sock )
          when :tund then
            read_tund( sock )
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
          when :dst then
            write_dst( sock )
          when :tcp then
            write_tcp( sock )
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

    def quit!
      # puts "debug exit"
      exit
    end

    private

    def add_dst_rbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :rbuff ] << data

      if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        puts "#{ Time.new } dst rbuff full"
        close_dst( dst )
      end
    end

    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        tun = dst_info[ :tun ]

        if tun then
          tun_info = @tun_infos[ tun ]

          if tun_info then
            puts "#{ Time.new } pause tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ] }"
            @reads.delete( tun )
            tun_info[ :paused ] = true
          end
        end
      end
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

    def add_tcp_wbuff( tcp, data )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :wbuff ] << data
      add_write( tcp )
    end

    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = tun_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ] }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
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
      return if dns.nil? || dns.closed?
      close_sock( dns )
      @dns_infos.delete( dns )
    end

    def close_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      @dst_infos.delete( dst )
    end

    def close_read_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close read dst"
      dst_info = @dst_infos[ dst ]

      if dst_info[ :wbuff ].empty? then
        close_dst( dst )
      else
        @reads.delete( dst )
      end
    end

    def close_read_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close read tun"
      tun_info = @tun_infos[ tun ]

      if tun_info[ :wbuff ].empty? then
        close_tun( tun )
      else
        @reads.delete( tun )
      end
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @updates.delete( sock )
      @roles.delete( sock )
    end

    def close_tcp( tcp )
      return if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      @tcp_infos.delete( tcp )
    end

    def close_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      @tun_infos.delete( tun )
    end

    def deal_ctlmsg( data, tcp )
      return if data.nil? || data.empty? || tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      ctl_chr = data[ 0 ]

      case ctl_chr
      when Girl::Custom::HELLO then
        return if tcp_info[ :im ]
        _, im = data.split( Girl::Custom::SEP )
        return unless im

        tcp_info[ :im ] = im
        im_info = @im_infos[ im ]

        unless im_info then
          im_info = {
            in: 0,
            out: 0
          }

          @im_infos[ im ] = im_info
        end

        print "#{ Time.new } got hello #{ im.inspect } im infos #{ @im_infos.size } updates #{ @updates.size } "
        puts "tcp infos #{ @tcp_infos.size } dst infos #{ @dst_infos.size } tun infos #{ @tun_infos.size } dns infos #{ @dns_infos.size }"
      when Girl::Custom::A_NEW_SOURCE then
        return unless tcp_info[ :im ]
        _, src_id, domain_port = data.split( Girl::Custom::SEP )
        return if src_id.nil? || domain_port.nil?
        src_id = src_id.to_i
        dst_info = @dst_infos.values.find{ | info | info[ :src_id ] == src_id }

        if dst_info then
          puts "#{ Time.new } dst info already exist, ignore a new source #{ src_id } #{ domain_port.inspect }"
          return
        end

        # puts "debug got a new source #{ tcp_info[ :im ].inspect } #{ src_id } #{ domain_port.inspect }"
        resolve_domain_port( domain_port, src_id, tcp )
      when Girl::Custom::SOURCE_CLOSED then
        return unless tcp_info[ :im ]
        _, src_id = data.split( Girl::Custom::SEP )
        return unless src_id
        # puts "debug got src closed #{ tcp_info[ :im ].inspect } #{ src_id }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_dst( dst )
      when Girl::Custom::SOURCE_CLOSED_READ then
        return unless tcp_info[ :im ]
        _, src_id = data.split( Girl::Custom::SEP )
        return unless src_id
        # puts "debug got src closed read #{ tcp_info[ :im ].inspect } #{ src_id }"
        dst, dst_info = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        
        if dst_info then
          dst_info[ :closing ] = true
          add_write( dst )
        end
      end
    end

    def loop_check_traff
      if @reset_traff_day > 0 then
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL

            if Time.new.day == @reset_traff_day then
              msg = {
                message_type: 'reset-traffic'
              }

              send_msg_to_infod( msg )
            end
          end
        end
      end
    end

    def new_a_dst( domain, ip, port, src_id, tcp )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      im = tcp_info[ :im ]

      begin
        dst = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ e.class } #{ im } #{ domain }:#{ port }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      
      begin
        destination_addr = Socket.sockaddr_in( port, ip )
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect destination #{ e.class } #{ im } #{ domain }:#{ port }"
        dst.close
        return
      end

      dst_id = rand( ( 2 ** 64 ) - 2 ) + 1

      dst_info = {
        dst_id: dst_id,   # dst_id
        im: im,           # 标识
        domain: domain,   # 目的地域名
        ip: ip,           # 目的地ip
        rbuff: '',        # 对应的tun没准备好，暂存读到的流量
        tun: nil,         # 对应的tun
        wbuff: '',        # 从tun读到的流量
        src_id: src_id,   # 近端src id
        connected: false, # 是否已连接
        closing: false,   # 准备关闭
        paused: false     # 已暂停
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      add_write( dst )

      data = [ Girl::Custom::PAIRED, src_id, dst_id ].join( Girl::Custom::SEP )
      # puts "debug add paired #{ im.inspect } #{ src_id } #{ dst_id } #{ ip }:#{ port }"
      add_tcp_wbuff( tcp, encode_a_msg( data ) )

      Thread.new do
        sleep EXPIRE_CONNECTING

        msg = {
          message_type: 'check-dst-connected',
          dst_id: dst_id
        }

        send_msg_to_infod( msg )
      end
    end

    def new_a_girl( girl_port )
      girl_addr = Socket.sockaddr_in( girl_port, '0.0.0.0' )
      girl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      girl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      girl.bind( girl_addr )
      puts "#{ Time.new } girl bind on #{ girl_port }"
      add_read( girl, :girl )
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( infod_addr )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_tcpd( tcpd_port )
      tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcpd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tcpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tcpd.bind( Socket.sockaddr_in( tcpd_port, '0.0.0.0' ) )
      tcpd.listen( 127 )
      puts "#{ Time.new } tcpd listen on #{ tcpd_port }"
      add_read( tcpd, :tcpd )
    end

    def new_a_tund( girl_port )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tund.bind( Socket.sockaddr_in( girl_port, '0.0.0.0' ) )
      tund.listen( 127 )
      add_read( tund, :tund )
    end

    def read_dns( dns )
      if dns.closed? then
        puts "#{ Time.new } read closed dns?"
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
        ip = seek_ip( data )
      rescue Exception => e
        puts "#{ Time.new } seek ip #{ e.class } #{ e.message }"
        close_dns( dns )
        return
      end

      dns_info = @dns_infos[ dns ]
      domain = dns_info[ :domain ]

      if ip then
        port = dns_info[ :port ]
        src_id = dns_info[ :src_id ]
        tcp = dns_info[ :tcp ]
        new_a_dst( domain, ip, port, src_id, tcp )
        @resolv_caches[ domain ] = [ ip, Time.new ]
      else
        puts "#{ Time.new } no ip in answer #{ domain }"
      end

      close_dns( dns )
    end

    def read_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } read closed dst?"
        return
      end

      dst_info = @dst_infos[ dst ]
      tun = dst_info[ :tun ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_tun_closing( tun )
        return
      end

      set_update( dst )
      @im_infos[ dst_info[ :im ] ][ :in ] += data.bytesize

      if tun && !tun.closed? then
        add_tun_wbuff( tun, encode( data ) )
      else
        # puts "debug add dst rbuff #{ data.bytesize }"
        add_dst_rbuff( dst, data )
      end
    end

    def read_girl( girl )
      data, addrinfo, rflags, *controls = girl.recvmsg
      return if data.empty?

      im = decode_im( data )
      return if @ims.any? && !@ims.include?( im )
      
      @ips[ im ] = addrinfo.ip_address
      puts "#{ Time.new } set ip #{ im.inspect } #{ addrinfo.ip_address } ips #{ @ips.size }"
    end

    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      return if data.empty?

      begin
        msg = JSON.parse( data, symbolize_names: true )
      rescue JSON::ParserError, EncodingError => e
        puts "#{ Time.new } read infod #{ e.class }"
        return
      end

      message_type = msg[ :message_type ]

      case message_type
      when 'check-dst-connected' then
        dst_id = msg[ :dst_id ]
        dst, dst_info = @dst_infos.find{ | _, _info | ( _info[ :dst_id ] == dst_id ) && !_info[ :connected ] }

        if dst then
          puts "#{ Time.new } dst connect timeout #{ dst_info[ :dst_id ] } #{ dst_info[ :domain ] }"
          close_dst( dst )
        end
      when 'check-dns-closed' then
        dns_id = msg[ :dns_id ]
        dns, dns_info = @dns_infos.find{ | _, _info | _info[ :dns_id ] == dns_id }

        if dns then
          puts "#{ Time.new } dns expired #{ dns_info[ :dns_id ] } #{ dns_info[ :domain ] }"
          close_dns( dns )
        end
      when 'check-tcp-im' then
        tcp_id = msg[ :tcp_id ]
        tcp, tcp_info = @tcp_infos.find{ | _, _info | ( _info[ :tcp_id ] == tcp_id ) && _info[ :im ].nil? }

        if tcp then
          puts "#{ Time.new } tcp expired #{ tcp_info[ :tcp_id ] }"
          close_tcp( tcp )
        end
      when 'check-tun-im' then
        tun_id = msg[ :tun_id ]
        tun, tun_info = @tun_infos.find{ | _, _info | ( _info[ :tun_id ] == tun_id ) && _info[ :im ].nil? }

        if tun then
          puts "#{ Time.new } tun expired #{ tun_info[ :tun_id ] }"
          close_tun( tun )
        end
      when 'reset-traffic' then
        puts "#{ Time.new } reset traffic"
        @im_infos.each{ | _, _info | _info[ :in ] = _info[ :out ] = 0 }
      when 'memory-info' then
        arr = []

        @im_infos.sort.map do | im, _info |
          arr << {
            im: im,
            in: _info[ :in ],
            out: _info[ :out ]
          }
        end

        msg2 = {
          sizes: {
            ips: @ips.size,
            im_infos: @im_infos.size,
            updates: @updates.size,
            tcp_infos: @tcp_infos.size,
            dst_infos: @dst_infos.size,
            tun_infos: @tun_infos.size,
            dns_infos: @dns_infos.size,
            resolv_caches: @resolv_caches.size
          },
          im_infos: arr
        }

        begin
          @infod.sendmsg_nonblock( JSON.generate( msg2 ), 0, addrinfo )
        rescue Exception => e
          puts "#{ Time.new } send memory info #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        end
      end
    end

    def read_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } read closed tcp?"
        return
      end

      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      set_update( tcp )
      tcp_info = @tcp_infos[ tcp ]
      data = "#{ tcp_info[ :part ] }#{ data }"

      msgs, part = decode_to_msgs( data )
      close_tcp( tcp ) if msgs.empty?
      msgs.each{ | msg | deal_ctlmsg( msg, tcp ) }
      tcp_info[ :part ] = part
    end

    def read_tcpd( tcpd )
      if tcpd.closed? then
        puts "#{ Time.new } read closed tcpd?"
        return
      end

      begin
        tcp, addrinfo = tcpd.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } tcpd accept #{ e.class }"
        return
      end

      unless @ips.values.include?( addrinfo.ip_address ) then
        puts "#{ Time.new } accept a tcp unknown ip? #{ addrinfo.ip_address }"
        tcp.close
        return
      end

      # puts "debug accept a tcp"
      tcp_id = rand( ( 2 ** 64 ) - 2 ) + 1

      @tcp_infos[ tcp ] = {
        tcp_id: tcp_id, # tcp id
        part: '',       # 包长+没收全的缓存
        wbuff: '',      # 写前
        im: nil         # 标识
      }
      
      add_read( tcp, :tcp )

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-tcp-im',
          tcp_id: tcp_id
        }

        send_msg_to_infod( msg )
      end
    end

    def read_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } read closed tun?"
        return
      end

      tun_info = @tun_infos[ tun ]

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_read_tun( tun )
        return
      end

      set_update( tun )
      dst = tun_info[ :dst ]

      unless dst then
        sep_idx = data.index( Girl::Custom::SEP )

        unless sep_idx then
          puts "#{ Time.new } miss ping sep?"
          close_tun( tun )
          return
        end

        dst_id = data[ 0, sep_idx ].to_i
        dst, dst_info = @dst_infos.find{ | _, info | info[ :dst_id ] == dst_id }

        unless dst then
          # puts "debug dst not found #{ dst_id }"
          close_tun( tun )
          return
        end

        tun_info[ :dst ] = dst
        tun_info[ :domain ] = dst_info[ :domain ]
        tun_info[ :im ] = dst_info[ :im ]
        set_dst_info_tun( dst_info, tun )
        data = data[ ( sep_idx + 1 )..-1 ]

        if data.empty? then
          return
        end
      end

      data = "#{ tun_info[ :part ] }#{ data }"
      data, part = decode( data )
      add_dst_wbuff( dst, data )
      tun_info[ :part ] = part
    end

    def read_tund( tund )
      if tund.closed? then
        puts "#{ Time.new } read closed tund?"
        return
      end

      begin
        tun, addrinfo = tund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } tund accept #{ e.class }"
        return
      end

      unless @ips.values.include?( addrinfo.ip_address ) then
        puts "#{ Time.new } accept a tun unknown ip? #{ addrinfo.ip_address }"
        tun.close
        return
      end

      # puts "debug accept a tun"
      tun_id = rand( ( 2 ** 64 ) - 2 ) + 1

      @tun_infos[ tun ] = {
        tun_id: tun_id, # tun id
        im: nil,        # 标识
        dst: nil,       # 对应dst
        domain: nil,    # 目的地
        part: '',       # 包长+没收全的缓存
        wbuff: '',      # 写前
        paused: false   # 是否暂停
      }

      add_read( tun, :tun )

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-tun-im',
          tun_id: tun_id
        }

        send_msg_to_infod( msg )
      end
    end

    def resolve_domain_port( domain_port, src_id, tcp )
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i

      if ( domain !~ /^[0-9a-zA-Z\-\.]{1,63}$/ ) || ( domain =~ /^(0\.\d{1,3}\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(169\.254\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(255\.255\.255\.255)|(localhost)$/ ) then
        # 忽略非法域名，内网地址
        puts "#{ Time.new } ignore #{ domain }"
        return
      end

      if domain =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/ then
        # ipv4
        new_a_dst( domain, domain, port, src_id, tcp )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain } hit resolv cache #{ ip }"
          new_a_dst( domain, ip, port, src_id, tcp )
          return
        end

        # puts "debug expire #{ domain } resolv cache"
        @resolv_caches.delete( domain )
      end

      begin
        data = pack_a_query( domain )
      rescue Exception => e
        puts "#{ Time.new } pack a query #{ e.class } #{ e.message } #{ domain }"
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain }"
        @nameserver_addrs.each{ | addr | dns.sendmsg_nonblock( data, 0, addr ) }
      rescue Exception => e
        puts "#{ Time.new } dns send data #{ e.class } #{ domain }"
        dns.close
        return
      end

      dns_id = rand( ( 2 ** 64 ) - 2 ) + 1

      dns_info = {
        dns_id: dns_id,
        src_id: src_id,
        domain: domain,
        port: port,
        tcp: tcp
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-dns-closed',
          dns_id: dns_id
        }

        send_msg_to_infod( msg )
      end
    end

    def send_msg_to_infod( msg )
      begin
        @info.sendmsg( JSON.generate( msg ), 0, @infod_addr )
      rescue Exception => e
        puts "#{ Time.new } send msg to infod #{ e.class }"
      end
    end

    def set_dst_info_tun( dst_info, tun )
      dst_info[ :tun ] = tun
      src_id = dst_info[ :src_id ]
      # puts "debug add pong #{ src_id }"
      data = "#{ src_id }#{ Girl::Custom::SEP }"

      unless dst_info[ :rbuff ].empty? then
        data << encode( dst_info[ :rbuff ] )
      end

      add_tun_wbuff( tun, data )
    end

    def set_tun_closing( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing ]
      # puts "debug set tun closing write"
      tun_info[ :closing ] = true
      add_write( tun )
    end

    def set_update( sock )
      if @updates.size >= @updates_limit then
        puts "#{ Time.new } eliminate updates"

        @updates.sort_by{ | _, updated_at | updated_at }.map{ | sock, _ | sock }[ 0, @eliminate_size ].each do | sock |
          case @roles[ sock ]
          when :dns
            close_dns( sock )
          when :dst
            close_dst( sock )
          when :tcp
            close_tcp( sock )
          when :tun
            close_tun( sock )
          end
        end
      end

      @updates[ sock ] = Time.new
    end

    def write_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } write closed dst?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
      tun = dst_info[ :tun ]
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
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_dst( dst )
        close_read_tun( tun )
        return
      end

      set_update( dst )
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @im_infos[ dst_info[ :im ] ][ :out ] += written

      if tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ] }"
          add_read( tun )
          tun_info[ :paused ] = false
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
        written = tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      set_update( tcp )
      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
      @im_infos[ tcp_info[ :im ] ][ :out ] += written
    end

    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write closed tun?"
        return
      end

      tun_info = @tun_infos[ tun ]
      dst = tun_info[ :dst ]
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
        written = tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tun #{ e.class }"
        close_tun( tun )
        close_read_dst( dst )
        return
      end

      set_update( tun )
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data

      if tun_info[ :im ] then
        @im_infos[ tun_info[ :im ] ][ :out ] += written
      end

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ] }"
          add_read( dst )
          dst_info[ :paused ] = false
        end
      end
    end

  end
end
