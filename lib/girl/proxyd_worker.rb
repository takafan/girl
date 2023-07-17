module Girl
  class ProxydWorker
    include Custom
    include Dns

    def initialize( proxyd_port, girl_port, nameservers, reset_traff_day, ims )
      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @reset_traff_day = reset_traff_day
      @ims = ims
      @update_roles = [ :dns, :dst, :tcp, :tun ] # 参与淘汰的角色
      @updates_limit = 1010 # 淘汰池上限，1015(mac) - [ girl, info, infod, tcpd, tund ]
      @reads = []           # 读池
      @writes = []          # 写池
      @updates = {}         # sock => updated_at
      @eliminate_count = 0  # 淘汰次数
      @roles = {}           # sock => :dns / :dst / :girl / :infod / :tcpd / :tcp / :tund / :tun
      @tcp_infos = {}       # tcp => { :part :wbuff :im }
      @resolv_caches = {}   # domain => [ ip, created_at ]
      @dst_infos = {}       # dst => { :dst_id :im :domain :ip :rbuff :tun :src_id :connected :wbuff :closing :paused :left }
      @tun_infos = {}       # tun => { :im :dst :domain :part :wbuff :closing :paused }
      @dns_infos = {}       # dns => { :dns_id :im :src_id :domain :port :tcp }
      @rsv_infos = {}       # rsv => { :rsv_id :im :near_id :domain :tcp  }
      @ips = {}             # im => ip
      @im_infos = {}        # im => { :in, :out }
      
      new_a_tcpd( proxyd_port )
      new_a_infod( proxyd_port )
      new_a_tund( girl_port )
      new_a_girl( girl_port )
    end

    def looping
      puts "#{ Time.new } looping"
      loop_check_expire
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
          when :rsv then
            read_rsv( sock )
          when :tcpd then
            read_tcpd( sock )
          when :tcp then
            read_tcp( sock )
          when :tund then
            read_tund( sock )
          when :tun then
            read_tun( sock )
          else
            # puts "#{ Time.new } read unknown role #{ role }"
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
            # puts "#{ Time.new } write unknown role #{ role }"
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
      return if dst.closed?

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
      return if tun.closed?

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
      return nil if dns.nil? || dns.closed?
      close_sock( dns )
      dns_info = @dns_infos.delete( dns )
      dns_info
    end

    def close_dst( dst )
      return nil if dst.nil? || dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      set_tun_closing( dst_info[ :tun ] ) if dst_info
      dst_info
    end

    def close_rsv( rsv )
      return nil if rsv.nil? || rsv.closed?
      # puts "debug close rsv"
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

    def close_tcp( tcp )
      return nil if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      tcp_info = @tcp_infos.delete( tcp )
      tcp_info
    end

    def close_tun( tun )
      return nil if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      tun_info = @tun_infos.delete( tun )
      set_dst_closing( tun_info[ :dst ] ) if tun_info
      tun_info
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

        puts "#{ Time.new } got hello #{ im.inspect }"
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

        # puts "debug got a new source #{ tcp_info[ :im ] } #{ src_id } #{ domain_port.inspect }"
        resolve_domain_port( domain_port, src_id, tcp, tcp_info[ :im ] )
      when Girl::Custom::QUERY then
        return unless tcp_info[ :im ]
        _, near_id, domain = data.split( Girl::Custom::SEP )
        return if near_id.nil? || domain.nil?
        new_a_rsv( domain, near_id, tcp, tcp_info[ :im ] )
      end
    end

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
        puts "#{ Time.new } new a dst #{ e.class } #{ im.inspect } #{ domain }:#{ port }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      
      begin
        destination_addr = Socket.sockaddr_in( port, ip )
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect destination #{ e.class } #{ im.inspect } #{ domain }:#{ port }"
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
        src_id: src_id,   # 近端src id
        connected: false, # 是否已连接
        wbuff: '',        # 写前
        closing: false,   # 是否准备关闭
        paused: false,    # 是否已暂停
        left: 0           # 剩余加密波数
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      add_write( dst )
      return if dst.closed?

      data = [ Girl::Custom::PAIRED, src_id, dst_id ].join( Girl::Custom::SEP )
      # puts "debug add paired #{ im.inspect } #{ src_id } #{ dst_id } #{ ip }:#{ port }"
      add_tcp_wbuff( tcp, encode_a_msg( data ) )
      return if tcp.closed?

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
      girl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      girl.bind( girl_addr )
      puts "#{ Time.new } girl bind on #{ girl_port }"
      add_read( girl, :girl )
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

    def new_a_rsv( domain, near_id, tcp, im )
      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        data = pack_a_query( domain )
      rescue Exception => e
        puts "#{ Time.new } pack a query #{ e.class } #{ e.message } #{ domain }"
        return
      end
      
      begin
        # puts "debug rsv query #{ domain }"
        @nameserver_addrs.each{ | addr | rsv.sendmsg_nonblock( data, 0, addr ) }
      rescue Exception => e
        puts "#{ Time.new } rsv send data #{ e.class }"
        rsv.close
        return
      end

      rsv_id = rand( ( 2 ** 64 ) - 2 ) + 1
      rsv_info = {
        rsv_id: rsv_id,
        im: im,
        near_id: near_id,
        domain: domain,
        tcp: tcp
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

        send_msg_to_infod( msg )
      end
    end

    def new_a_tcpd( tcpd_port )
      tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcpd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tcpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      tcpd.bind( Socket.sockaddr_in( tcpd_port, '0.0.0.0' ) )
      tcpd.listen( BACKLOG )
      puts "#{ Time.new } tcpd listen on #{ tcpd_port }"
      add_read( tcpd, :tcpd )
    end

    def new_a_tund( girl_port )
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      tund.bind( Socket.sockaddr_in( girl_port, '0.0.0.0' ) )
      tund.listen( BACKLOG )
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

      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_dst( dst )
        return
      end

      set_update( dst )
      dst_info = @dst_infos[ dst ]
      @im_infos[ dst_info[ :im ] ][ :in ] += data.bytesize
      tun = dst_info[ :tun ]

      if tun then
        if dst_info[ :left ] > 0 then
          data = encode( data )
          dst_info[ :left ] -= 1
          data << Girl::Custom::TERM if dst_info[ :left ] == 0
        end

        add_tun_wbuff( tun, data )
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
      # puts "debug set ip #{ im.inspect } #{ addrinfo.ip_address } ips #{ @ips.size }"
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
          puts "#{ Time.new } dst connect timeout #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ] }"
          close_dst( dst )
        end
      when 'check-dns-closed' then
        dns_id = msg[ :dns_id ]
        dns, dns_info = @dns_infos.find{ | _, _info | _info[ :dns_id ] == dns_id }

        if dns then
          puts "#{ Time.new } dns expired #{ dns_info[ :dns_id ] } #{ dns_info[ :im ] } #{ dns_info[ :domain ] }"
          close_dns( dns )
        end
      when 'check-expire' then
        now = Time.new
        socks = @updates.select{ | _, updated_at | now - updated_at >= EXPIRE_AFTER }.keys

        if socks.any? then
          dns_count = dst_count = rsv_count = tcp_count = tun_count = 0

          socks.each do | sock |
            case @roles[ sock ]
            when :dns
              close_dns( sock )
              dns_count += 1
            when :dst
              close_dst( sock )
              dst_count += 1
            when :rsv
              close_rsv( sock )
              rsv_count += 1
            when :tcp
              close_tcp( sock )
              tcp_count += 1
            when :tun
              close_tun( sock )
              tun_count += 1
            else
              close_sock( sock )
            end
          end

          # puts "debug expire dns #{ dns_count } dst #{ dst_count } tcp #{ tcp_count } tun #{ tun_count }"
        end
      when 'check-rsv-closed' then
        rsv_id = msg[ :rsv_id ]
        rsv, rsv_info = @rsv_infos.find{ | _, _info | _info[ :rsv_id ] == rsv_id }

        if rsv then
          puts "#{ Time.new } rsv expired #{ rsv_info[ :rsv_id ] } #{ rsv_info[ :im ] } #{ rsv_info[ :domain ] }"
          close_rsv( rsv )
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
            rsv_infos: @rsv_infos.size,
            resolv_caches: @resolv_caches.size
          },
          updates_limit: @updates_limit,
          eliminate_count: @eliminate_count,
          im_infos: arr
        }

        begin
          @infod.sendmsg_nonblock( JSON.generate( msg2 ), 0, addrinfo )
        rescue Exception => e
          puts "#{ Time.new } send memory info #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        end
      end
    end

    def read_rsv( rsv )
      if rsv.closed? then
        puts "#{ Time.new } read closed rsv?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "#{ Time.new } rsv recvmsg #{ e.class }"
        close_rsv( rsv )
        return
      end

      return if data.empty?

      rsv_info = @rsv_infos[ rsv ]
      near_id = rsv_info[ :near_id ]
      im = rsv_info[ :im ]
      domain = rsv_info[ :domain ]
      tcp = rsv_info[ :tcp ]
      limit = Girl::Custom::CHUNK_SIZE - 4 - near_id.to_s.size

      if data.bytesize > limit then
        part = data[ 0, limit ]
        data = data[ limit..-1 ]
        data2 = [ Girl::Custom::INCOMPLETE, near_id, part ].join( Girl::Custom::SEP )
        puts "#{ Time.new } incomplete #{ near_id } #{ im.inspect } #{ domain } #{ part.bytesize }"
        add_tcp_wbuff( tcp, encode_a_msg( data2 ) )
      end

      data2 = [ Girl::Custom::RESPONSE, near_id, data ].join( Girl::Custom::SEP )
      puts "#{ Time.new } response #{ near_id } #{ im.inspect } #{ domain } #{ data.bytesize }"
      add_tcp_wbuff( tcp, encode_a_msg( data2 ) )
      close_rsv( rsv )
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
      return if tcp.closed?

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

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_tun( tun )
        return
      end

      set_update( tun )
      tun_info = @tun_infos[ tun ]
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

      if tun_info[ :part ] != Girl::Custom::TERM then
        data = "#{ tun_info[ :part ] }#{ data }"
        data, part = decode( data )
        tun_info[ :part ] = part
      end

      add_dst_wbuff( dst, data )
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
        closing: false, # 是否准备关闭
        paused: false   # 是否已暂停
      }

      add_read( tun, :tun )
      return if tun.closed?

      Thread.new do
        sleep EXPIRE_NEW

        msg = {
          message_type: 'check-tun-im',
          tun_id: tun_id
        }

        send_msg_to_infod( msg )
      end
    end

    def resolve_domain_port( domain_port, src_id, tcp, im )
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
        im: im,
        domain: domain,
        port: port,
        tcp: tcp
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )
      return if dns.closed?

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
      dst_info[ :left ] = Girl::Custom::WAVE
      src_id = dst_info[ :src_id ]
      # puts "debug add pong #{ src_id }"
      data = "#{ src_id }#{ Girl::Custom::SEP }"
      data2 = dst_info[ :rbuff ]

      unless data2.empty? then
        if dst_info[ :left ] > 0 then
          data << encode( data2 )
          dst_info[ :left ] -= 1
          data << Girl::Custom::TERM if dst_info[ :left ] == 0
        else
          data << data2
        end
      end

      add_tun_wbuff( tun, data )
    end

    def set_dst_closing( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info.nil? || dst_info[ :closing ]
      dst_info[ :closing ] = true
      add_write( dst )
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
          when :tcp
            close_tcp( _sock )
          when :tun
            close_tun( _sock )
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
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_dst( dst )
        return
      end

      set_update( dst )
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @im_infos[ dst_info[ :im ] ][ :out ] += written
      tun = dst_info[ :tun ]

      if tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun #{ tun_info[ :im ].inspect } #{ tun_info[ :domain ] }"
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
        return
      end

      set_update( tun )
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data

      if tun_info[ :im ] then
        @im_infos[ tun_info[ :im ] ][ :out ] += written
      end

      dst = tun_info[ :dst ]

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]

        if dst_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ] }"
          add_read( dst )
          dst_info[ :paused ] = false unless dst.closed?
        end
      end
    end

  end
end
